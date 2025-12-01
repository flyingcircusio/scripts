#!/usr/bin/env python3

import argparse
import asyncio
import os
import struct
import subprocess
import sys
from contextlib import asynccontextmanager

import asyncio_dgram as aioudp

INLINE_SCRIPT = """\
import os
import select
import socket
import struct
import sys
port = int(sys.argv[1])
stdin = sys.stdin.fileno()
stdout = sys.stdout.fileno()
sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.setblocking(False)
os.set_blocking(stdin, False)
read = 0
while True:
    fds, _, _ = select.select([stdin, sock.fileno()], [], [])
    if sock.fileno() in fds:
        data, _ = sock.recvfrom(1280)
        head = struct.pack("!H", len(data))
        os.write(stdout, head + data)
    if stdin in fds:
        data = os.read(stdin, read if read else 2)
        if not data:
            sys.exit(0)
        if read:
            sock.sendto(data, ("127.0.0.1", port))
            read = 0
        else:
            read = struct.unpack("!H", data)
            read = read[0]
"""

LOCALE_VARS = [
    "LANG",
    "LANGUAGE",
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
    "LC_ALL",
]


async def udp_to_ssh(sock, writer, reader):
    task = None
    oaddr = None
    try:
        while True:
            data, addr = await sock.recv()
            if oaddr != addr:
                if task:
                    task.cancel()
                task = asyncio.create_task(ssh_to_udp(sock, addr, reader))
            oaddr = addr
            head = struct.pack("!H", len(data))
            writer.write(head + data)
            await writer.drain()
    except asyncio.CancelledError:
        if task:
            task.cancel()


async def length_prefixed_read(reader):
    data = await reader.read(2)
    if not data:
        return
    length = struct.unpack("!H", data)
    length = length[0]
    data = await reader.read(length)
    return data


async def ssh_to_udp(sock, addr, reader):
    read = 0
    try:
        while True:
            # protect against cancellation between reading the length
            # of the payload and reading the payload itself in order
            # to prevent the ssh stream read getting desynchronised.
            data = await asyncio.shield(length_prefixed_read(reader))
            if not data:
                return
            await sock.send(data, addr)
    except asyncio.CancelledError:
        pass


class SshManager:
    def __init__(self, args):
        self.args = args
        self.proc = None

    async def ssh(self, cmd=None, flags=None, check_output=False, cpath_force=False):
        argv = []
        argv.append(self.args.ssh)

        # if we haven't started the manager process yet or it's
        # started and running then set the path to the control
        # socket. only when it's exited already (e.g. connection lost)
        # should we ignore the control path.
        if cpath_force or self.proc is None or self.proc.returncode is None:
            argv.extend(["-o", f"ControlPath={self.args.ssh_socket_path}"])

        if flags:
            argv.extend(flags)

        for option in self.args.ssh_options:
            argv.extend(["-o", option])

        if self.args.proxy_jump:
            argv.extend(["-J", self.args.proxy_jump])

        if self.args.login_user:
            argv.extend(["-l", self.args.login_user])

        argv.extend(["--", self.args.hostname])

        if cmd:
            argv.extend(cmd)

        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )

        if check_output:
            stdout, _ = await proc.communicate()
            if proc.returncode:
                raise RuntimeError(
                    "ssh exited with error: {}: {}".format(
                        proc.returncode, " ".join(argv)
                    )
                )
            return stdout.decode()
        else:
            return proc

    async def __aenter__(self):
        self.proc = await self.ssh(None, ["-o", "ControlMaster=yes", "-N"])
        setup = False
        for count in range(self.args.wait):
            check = await self.ssh(None, ["-O", "check"])
            await check.wait()
            if not check.returncode:
                setup = True
                break
            await asyncio.sleep(1)

        if not setup:
            self.proc.terminate()
            raise RuntimeError(
                f"Timed out waiting for ssh control master to connect: {self.args.wait}s"
            )

        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if self.proc and self.proc.returncode is None:
            exit_ = await self.ssh(None, ["-O", "exit"], cpath_force=True)
            await exit_.wait()
            await self.proc.wait()

    async def packet_proxy(self, sock, server_port):
        task = None
        proc = None
        controlmaster_waited = False
        try:
            while True:
                proc = await self.ssh(
                    [self.args.python, "-c", f"'{INLINE_SCRIPT}'", server_port]
                )
                task = asyncio.create_task(udp_to_ssh(sock, proc.stdin, proc.stdout))
                await proc.wait()
                task.cancel()
                task = None
                # clean up after control master process if it's
                # dead
                if not controlmaster_waited and self.proc.returncode is not None:
                    await self.proc.wait()
                    controlmaster_waited = True
                print("ssh subprocess died, waiting and restarting", file=sys.stderr)
                # XXX exponential backoff
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            if task:
                task.cancel()
            if proc and proc.returncode is None:
                proc.terminate()
                await asyncio.shield(proc.wait())


async def mosh_terminal_colours(args):
    proc = await asyncio.create_subprocess_exec(
        *[args.mosh_client, "-c"], stdout=asyncio.subprocess.PIPE
    )

    stdout, _ = await proc.communicate()

    if proc.returncode:
        raise RuntimeError(f"mosh-client exited with error: {proc.returncode}")

    return stdout.decode().strip()


def make_mosh_args(args, environ, colours):
    argv = []
    argv.extend([args.mosh_server, "new"])
    argv.extend(["-c", colours])
    argv.extend(["-i", "127.0.0.1"])
    for var in LOCALE_VARS:
        if var in environ:
            value = environ[var]
            argv.extend(["-l", f"{var}={value}"])
    return argv


async def main_coro(args, environ):
    colours = await mosh_terminal_colours(args)

    mosh_args = make_mosh_args(args, environ, colours)
    if args.nix_shell:
        mosh_args = [
            "nix-shell",
            "-p",
            "mosh",
            "--run",
            "'env -u TMP -u TEMP -u TMPDIR -u TEMPDIR {}'".format(" ".join(mosh_args)),
        ]

    endpoint = await aioudp.bind(("localhost", 0))

    async with SshManager(args) as manager:
        server_info = await manager.ssh(mosh_args, check_output=True)
        server_info = [
            line for line in server_info.splitlines() if line.startswith("MOSH CONNECT")
        ]

        if not server_info:
            raise RuntimeError("Could not read mosh-server info")
        server_info = server_info[0].split()
        if len(server_info) != 4:
            raise RuntimeError(f"Unexpected mosh-server conection info: {server_info}")
        server_port = server_info[2]
        session_key = server_info[3]

        mosh_environ = environ.copy()
        mosh_environ["MOSH_KEY"] = session_key
        mosh_args = [args.mosh_client, endpoint.sockname[0], str(endpoint.sockname[1])]

        async with asyncio.TaskGroup() as tg:
            proxy_task = tg.create_task(manager.packet_proxy(endpoint, server_port))
            mosh_proc = await asyncio.create_subprocess_exec(
                *mosh_args, env=mosh_environ
            )
            await mosh_proc.wait()
            proxy_task.cancel()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="mosh-tunnel", description="Use SSH to tunnel mosh to a remote host"
    )

    parser.add_argument(
        "-m",
        "--mosh-client-path",
        dest="mosh_client",
        default="mosh-client",
        metavar="PATH",
        help="Path to local mosh-client binary",
    )
    parser.add_argument(
        "-M",
        "--mosh-server-path",
        dest="mosh_server",
        default="mosh-server",
        metavar="PATH",
        help="Path to remote mosh-server binary",
    )
    parser.add_argument(
        "-s",
        "--ssh-path",
        dest="ssh",
        default="ssh",
        metavar="PATH",
        help="Path to SSH client",
    )
    parser.add_argument(
        "-P",
        "--python-path",
        dest="python",
        default="python3",
        metavar="PATH",
        help="Path to remote python3 interpreter",
    )
    parser.add_argument(
        "-n",
        "--nix-shell",
        action="store_true",
        default=False,
        help="Use nix-shell to invoke mosh-server on the remote host",
    )
    parser.add_argument(
        "-p",
        "--ssh-socket-path",
        default="~/.ssh/mosh-tunnel/%C",
        metavar="PATH",
        help="Path for SSH ControlMaster socket (passed to ssh ControlPath; default: ~/.ssh/mosh-tunnel/%%C)",
    )
    parser.add_argument(
        "-o",
        "--ssh-option",
        dest="ssh_options",
        action="append",
        default=[],
        metavar="OPTION",
        help="Pass additional configuration option to the SSH client (may be specified multiple times)",
    )
    parser.add_argument(
        "-J",
        "--proxy-jump",
        metavar="HOST",
        help="Pass HOST as ProxyJump option to SSH client",
    )
    parser.add_argument(
        "-l", "--login-user", metavar="USER", help="SSH login user for the remote host"
    )
    parser.add_argument(
        "-w",
        "--wait",
        default=10,
        type=int,
        metavar="SEC",
        help="Wait up to SEC seconds for the SSH ControlMaster to establish a connection to the remote host",
    )
    parser.add_argument("hostname", metavar="HOSTNAME")

    args = parser.parse_args()

    # copy environment variables before jumping into async land
    environ = os.environ.copy()

    asyncio.run(main_coro(args, environ))

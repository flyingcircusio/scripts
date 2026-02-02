#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import socket
import select

INLINE_SCRIPT = """\
import socket
import select
import os
import sys
import json
import subprocess
import time
conn = os.getenv("SSH_CONNECTION")
if not conn:
    print("could not read ssh connection info", file=sys.stderr)
    sys.exit(1)
conn = conn.split()[2]
try:
    data = subprocess.check_output(["ip", "-j", "address", "show", "scope", "global", "-deprecated"])
    data = json.loads(data)
except Exception:
    print("could not read ip address info", file=sys.stderr)
    sys.exit(1)
addrs = []
for iface in data:
    if any(map(lambda info: (info["local"] == conn) if "local" in info else False, iface["addr_info"])):
        for info in iface["addr_info"]:
            if "local" not in info:
                continue
            addrs.append(info["local"])
        break
if not addrs:
    print("could not find interface for ssh connection", file=sys.stderr)
    sys.exit(1)
local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ipv4_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ipv6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
    local_sock.bind(("127.0.0.1", 0))
except Exception as exc:
    print("could not bind local socket: {}".format(exc), file=sys.stderr)
    sys.exit(1)
for sock, addr in [(ipv4_sock, "0.0.0.0"), (ipv6_sock, "::")]:
    bound = False
    for port in range(60000, 61000):
        try:
            sock.bind((addr, port))
            bound = True
            break
        except Exception:
            pass
    if not bound:
        print("could not find available port for socket: {}".format(addr), file=sys.stderr)
        sys.exit(1)
try:
    lines = subprocess.check_output(sys.argv[1:], text=True)
except Exception:
    print("could not start mosh-server", file=sys.stderr)
    sys.exit(1)
lines = lines.splitlines()
lines = [line for line in lines if line.startswith("MOSH CONNECT")]
if not lines:
    print("could not process mosh banner", file=sys.stderr)
    sys.exit(1)
info = lines[0]
info = info.split()
if len(info) != 4:
    print("could not find mosh session key", file=sys.stderr)
    sys.exit(1)
target_port = int(info[2])
session_key = info[3]
data = dict(key=session_key, port4=ipv4_sock.getsockname()[1], port6=ipv6_sock.getsockname()[1], addrs=addrs)
json.dump(data, sys.stdout)
pid = os.fork()
if pid == -1:
    sys.exit(1)
elif pid > 0:
    sys.exit(0)
for f in [sys.stdin, sys.stdout, sys.stderr]:
    os.close(f.fileno())
os.setsid()
pid = os.fork()
if pid == -1 or pid > 0:
    sys.exit(0)
last_addr = None
last_sock = None
last_time = int(time.time())
start = last_time
while True:
    fds, _, _ = select.select([local_sock, ipv4_sock, ipv6_sock], [], [], 1)
    now = int(time.time())
    if last_addr is None:
        if now - start > 60:
            sys.exit(1)
    elif now - last_time > 604800:
        sys.exit(0)
    if local_sock in fds:
        data, _ = local_sock.recvfrom(1280)
        last_sock.sendto(data, last_addr)
    for sock in [ipv6_sock, ipv4_sock]:
        if sock in fds:
            data, addr = sock.recvfrom(1280)
            local_sock.sendto(data, ("127.0.0.1", target_port))
            if addr != last_addr:
                last_addr = addr
            last_sock = sock
            last_time = now
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


def make_mosh_args(args, colours):
    argv = []
    argv.extend([args.mosh_server, "new"])
    argv.extend(["-c", colours])
    argv.extend(["-i", "127.0.0.1"])
    for var in LOCALE_VARS:
        if var in os.environ:
            value = os.environ[var]
            argv.extend(["-l", f"{var}={value}"])
    return argv


def make_ssh_args(args, cmd):
    argv = []
    argv.append(args.ssh)
    for option in args.ssh_options:
        argv.extend(["-o", option])
    if args.login_user:
        argv.extend(["-l", args.login_user])
    argv.extend(["--", args.hostname])
    argv.extend(cmd)
    return argv


def bind_sockets(targets):
    sockmap = {}
    for target in targets:
        sock = socket.socket(
            socket.AF_INET6 if ":" in target[0] else socket.AF_INET, socket.SOCK_DGRAM
        )
        sock.bind(("::" if ":" in target[0] else "0.0.0.0", 0))
        sockmap[sock] = target
    return sockmap


def main(args):
    colours = subprocess.check_output([args.mosh_client, "-c"], text=True)
    colours = colours.strip()

    mosh_args = make_mosh_args(args, colours)
    if args.nix_shell:
        mosh_args = [
            "nix-shell",
            "-p",
            "mosh",
            "--run",
            "'{}'".format(" ".join(mosh_args)),
        ]

    remote_cmd = [args.python, "-c", f"'{INLINE_SCRIPT}'"]
    remote_cmd.extend(mosh_args)
    ssh_args = make_ssh_args(args, remote_cmd)

    data = subprocess.check_output(ssh_args)
    data = json.loads(data)

    environ = os.environ.copy()
    environ["MOSH_KEY"] = data["key"]

    targets = [
        (addr, data["port6"] if ":" in addr else data["port4"])
        for addr in data["addrs"]
    ]

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_sock.bind(("127.0.0.1", 0))
    mosh_port = local_sock.getsockname()[1]

    proc = subprocess.Popen(
        [args.mosh_client, "127.0.0.1", str(mosh_port)], env=environ
    )

    sockmap = {}
    last_addr = None
    last_sock = None
    skip_sock = None
    while True:
        reads = [local_sock]
        reads.extend(sockmap.keys())
        fds, _, _ = select.select(reads, [], [], 1)

        if proc.poll() is not None:
            local_sock.close()
            for sock in sockmap.keys():
                sock.close()
            return proc.returncode

        for sock, target in sockmap.items():
            if sock in fds:
                data, addr = sock.recvfrom(1280)
                if addr[0] != sockmap[sock][0] or addr[1] != sockmap[sock][1]:
                    # ignore packets from unexpected endpoint
                    continue
                local_sock.sendto(data, last_addr)
                last_sock = sock

        if local_sock in fds:
            data, addr = local_sock.recvfrom(1280)
            if addr != last_addr:
                # mosh-client has jumped ports, rebind
                for sock in sockmap.keys():
                    sock.close()
                sockmap = bind_sockets(targets)
                last_sock = None
                last_addr = addr
            if last_sock:
                try:
                    last_sock.sendto(data, sockmap[last_sock])
                except Exception:
                    # could not send, fall back to broadcast
                    skip_sock = last_sock
                    last_sock = None
            if not last_sock:
                # no last socket, broadcast packets
                for sock, target in sockmap.items():
                    if sock is skip_sock:
                        skip_sock = None
                        continue
                    try:
                        sock.sendto(data, target)
                    except Exception:
                        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="mosh-dualstack-proxy")

    parser.add_argument(
        "-m", "--mosh-client-path", dest="mosh_client", default="mosh-client"
    )
    parser.add_argument(
        "-M", "--mosh-server-path", dest="mosh_server", default="mosh-server"
    )
    parser.add_argument("-S", "--ssh-path", dest="ssh", default="ssh")
    parser.add_argument("-P", "--python-path", dest="python", default="python3")
    parser.add_argument("-n", "--nix-shell", action="store_true", default=False)
    parser.add_argument("-l", "--login-user")
    parser.add_argument(
        "-o", "--ssh-option", dest="ssh_options", action="append", default=[]
    )
    parser.add_argument("hostname", metavar="HOSTNAME")

    args = parser.parse_args()

    sys.exit(main(args))

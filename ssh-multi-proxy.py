#!/usr/bin/env python3

import argparse
import asyncio
import contextlib
import functools
import hashlib
import ipaddress
import logging
import os
import os.path
import random
import signal
import socket
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager, contextmanager

logging.basicConfig(format="ssh-multi-proxy[%(process)d]: %(message)s")
logger = logging.getLogger(__name__)

# XXX(sysvinit): support inline port specifications, support inline
# usernames in proxy specs.
SSH_PORT = 22

SOCKET_CONNECT_TIMEOUT = 10
SOCKET_PROXY_ACCEPT_TIMEOUT = 2
SOCKET_PROXY_SEND_FD_TIMEOUT = 2
SOCKET_PROXY_RECV_FD_TIMEOUT = 2
SSH_READINESS_FD_SEND_TIMEOUT = 2
SSH_READINESS_WAIT_TIMEOUT = 10
SSH_PROXY_FD_SEND_TIMEOUT = 2

ENV_SKIP_FIRST_DIRECT = "SSH_PROXY_SKIP_FIRST_DIRECT"
ENV_SUPPRESS_LOGGING = "SSH_PROXY_QUIET"


def make_socket_hash(hostname, address):
    rand = random.randrange(65536)
    h = hashlib.md5()
    h.update(hostname.encode("utf-8"))
    h.update(address.encode("utf-8"))
    h.update(str(rand).encode("utf-8"))
    return h.hexdigest()[:16]


def is_private_ipv4_address(addr):
    addr = ipaddress.ip_address(addr)
    return isinstance(addr, ipaddress.IPv4Address) and addr.is_private


# sendmsg and recvmsg are not implemented in asyncio, and cpython
# seems unwilling to add them to the standard library due to
# maintenance overhead.


async def sock_send_fds(sock, bufs, fds):
    if sock.gettimeout() != 0:
        raise ValueError("the socket must be non-blocking")
    try:
        return socket.send_fds(sock, bufs, fds)
    except (BlockingIOError, InterruptedError):
        pass

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fd = sock.fileno()

    loop.add_writer(fd, sock_send_fds_cb, fut, sock, bufs, fds)
    fut.add_done_callback(lambda _: loop.remove_writer(fd))
    return await fut


def sock_send_fds_cb(fut, sock, bufs, fds):
    try:
        data = socket.send_fds(sock, bufs, fds)
    except (BlockingIOError, InterruptedError):
        return
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:
        fut.set_exception(exc)
    else:
        fut.set_result(data)


async def sock_recv_fds(sock, bufsz, maxfds):
    if sock.gettimeout() != 0:
        raise ValueError("the socket must be non-blocking")
    try:
        data = socket.recv_fds(sock, bufsz, maxfds)
        return data
    except (BlockingIOError, InterruptedError):
        pass

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fd = sock.fileno()

    loop.add_reader(fd, sock_recv_fds_cb, fut, sock, bufsz, maxfds)
    fut.add_done_callback(lambda _: loop.remove_reader(fd))
    return await fut


def sock_recv_fds_cb(fut, sock, bufsz, maxfds):
    try:
        data = socket.recv_fds(sock, bufsz, maxfds)
    except (BlockingIOError, InterruptedError):
        return
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:
        fut.set_exception(exc)
    else:
        fut.set_result(data)


async def wait_first_nonempty(tasks):
    while tasks:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception() is None:
                result = task.result()
                if result is not None:
                    for p in pending:
                        p.cancel()
                    return result
            else:
                logger.debug("task threw exception: %s", task.exception())
        tasks = pending
    return None


def propagate_cancellation(task, subtask, fut):
    if task.cancelled():
        subtask.cancel()


def create_subtask(coro):
    task = asyncio.current_task()
    subtask = asyncio.create_task(coro)
    task.add_done_callback(functools.partial(propagate_cancellation, task, subtask))
    return subtask


async def connect_address(addr, delay):
    loop = asyncio.get_running_loop()
    sock = socket.socket(addr[0], addr[1], addr[2])
    sock.setblocking(False)
    logger.debug("connecting: %s: %s", addr[3], addr[4][0])
    try:
        if delay:
            await asyncio.sleep(delay)
        await asyncio.wait_for(
            loop.sock_connect(sock, addr[4]),
            SOCKET_CONNECT_TIMEOUT,
        )
    except OSError as exc:
        logger.debug("could not connect: %s: %s", addr[4], exc.strerror)
        sock.close()
        return None
    except asyncio.CancelledError:
        sock.close()
        raise
    logger.debug("connected: %s: %s", addr[3], addr[4][0])
    return (sock, addr)


async def resolve_hostname(args, hostname, port):
    loop = asyncio.get_running_loop()
    logger.debug("resolving hostname: %s", hostname)
    try:
        addrs = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            flags=socket.AI_CANONNAME,
        )
    except Exception as exc:
        logger.debug("could not resolve %s: %s", hostname, exc)
        return None

    result = []
    saddrs = []

    # getaddrinfo only sets the canonical name in the first returned
    # record, so we populate the field in the remaining records
    canonname = None
    for addr in addrs:
        family, type_, proto, name, saddr = addr
        if name != "":
            canonname = name
        else:
            name = canonname
        if args.skip_private_ipv4 and is_private_ipv4_address(saddr[0]):
            continue
        result.append((family, type_, proto, name, saddr))
        saddrs.append(saddr[0])

    logger.debug("resolved: %s: %s", hostname, ", ".join(saddrs))
    return result


def mixed_address_families(addrs):
    return functools.reduce(
        lambda prev, next: (
            (False, next[0])
            if prev is None
            else (prev[0] or prev[1] != next[0], next[0])
        ),
        addrs,
        None,
    )[0]


async def parallel_connect(args, addrs):
    delay = args.fallback_delay / 1000
    fast_fallback = mixed_address_families(addrs)
    tasks = map(
        lambda addr: create_subtask(
            connect_address(
                addr,
                delay if addr[0] == socket.AF_INET and fast_fallback else 0,
            )
        ),
        addrs,
    )
    return await wait_first_nonempty(tasks)


async def connect_direct_one(args, hostname, port):
    addrs = await resolve_hostname(args, hostname, port)
    if addrs is None:
        return None
    logger.debug("connecting sockets: %s", hostname)
    return await parallel_connect(args, addrs)


async def connect_direct(args):
    hostnames = []
    if ENV_SKIP_FIRST_DIRECT in os.environ:
        logger.debug(
            "ignoring primary hostname, falling back to alternative names: %s",
            args.hostname,
        )
    else:
        hostnames.append(args.hostname)
    if args.alt_names is not None:
        hostnames.extend(args.alt_names)

    if not hostnames:
        logger.debug(
            "primary hostname ignored and no altnames provided: %s", args.hostname
        )
        return None

    logger.debug("connecting to hosts: %s", ", ".join(hostnames))
    tasks = map(
        lambda host: create_subtask(connect_direct_one(args, host, args.port)),
        hostnames,
    )
    return await wait_first_nonempty(tasks)


@contextmanager
def passthrough_socket(path):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        sock.bind(path)
        sock.listen(1)
        sock.setblocking(False)
    except OSError as exc:
        logger.debug("could not bind socket: %s: %s", path, exc)
        raise

    try:
        yield sock
    finally:
        sock.close()
        os.unlink(path)

@asynccontextmanager
async def wrap_ssh_readiness_setup(sock, jumphost):
    sock.setblocking(False)

    with contextlib.closing(sock):
        yield

        logger.debug("waiting for ssh to indicate readiness for jumphost: %s", jumphost)

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.sock_recv(sock, 1), SSH_READINESS_WAIT_TIMEOUT
            )
        except TimeoutError:
            logger.debug(
                "did not recieve readiness notification from ssh: %s: operation timed out",
                jumphost,
            )
            raise
        except OSError as exc:
            logger.debug(
                "did not receive readiness notification from ssh: %s: %s",
                jumphost,
                exc.strerror,
            )
            raise

    logger.debug("ssh indicated forwarding readiness for jumphost: %s", jumphost)


@asynccontextmanager
async def connect_ssh(args, ssh_hostname, fwd_target, extra_args=[]):
    ssh_args = [
        args.ssh_path,
        # avoid interactive prompts
        "-ostricthostkeychecking=yes",
        "-W",
        "{}:{}".format(
            f"[{fwd_target}]" if ":" in fwd_target else fwd_target, args.port
        ),
    ]
    if args.wait_readiness:
        ssh_args.append("-r")
    if "master" in args.jump_indirection:
        ssh_args.extend(
            [
                "-ocontrolmaster=auto",
                f"-ocontrolpath={args.control_path}",
                f"-ocontrolpersist={args.control_persist}",
            ]
        )
    if args.proxy_username is not None:
        ssh_args.extend(["-l", args.proxy_username])
    if extra_args:
        ssh_args.extend(extra_args)
    ssh_args.extend(["--", ssh_hostname])

    parent, child = socket.socketpair()
    parent.setblocking(False)

    if args.verbose:
        stderr = None
    else:
        stderr = subprocess.DEVNULL

    if args.wait_readiness:
        read, write = socket.socketpair()
        n = write.fileno()
        def preexec():
            os.dup2(n, 3)
            os.set_inheritable(3, True)
    else:
        read, write = None, None
        preexec = None

    logger.debug("spawning ssh for jumphost: %s: %s", ssh_hostname, " ".join(ssh_args))

    try:
        proc = await asyncio.create_subprocess_exec(
            *ssh_args, stdin=child, stdout=child, stderr=stderr, preexec_fn=preexec, close_fds=False
        )
    except asyncio.CancelledError:
        parent.close()
        if read:
            read.close()
        raise
    except Exception as exc:
        logger.debug("could not spawn ssh for jumphost: %s: %s", ssh_hostname, exc)
        parent.close()
        if read:
            read.close()
        raise
    finally:
        child.close()
        if write:
            write.close()

    logger.debug("spawned ssh for jumphost: %s", ssh_hostname)

    try:
        if args.wait_readiness:
            async with wrap_ssh_readiness_setup(read, ssh_hostname):
                yield proc, parent
        else:
            yield proc, parent
    except:
        proc.terminate()
        await asyncio.shield(proc.wait())
        parent.close()


async def connect_jumphost_controlmaster(args, jumphost, target):
    # there's an inherent toctou race between checking if a control
    # master is already running and then actually opening a new
    # connection through it. however, this is only intended to work on
    # a best-effort basis in order to avoid hammering jump host sshds
    # and either triggering maxstartups throttling or fail2ban.

    ssh_args = [
        args.ssh_path,
        "-ocontrolmaster=auto",
        f"-ocontrolpath={args.control_path}",
        f"-ocontrolpersist={args.control_persist}",
        "-O",
        "check",
    ]
    if args.proxy_username is not None:
        ssh_args.extend(["-l", args.proxy_username])
    ssh_args.extend(["--", jumphost])
    if args.verbose:
        stderr = None
    else:
        stderr = subprocess.DEVNULL

    logger.debug(
        "spawning ssh to check controlmaster for jumphost: %s: %s",
        jumphost,
        " ".join(ssh_args),
    )

    try:
        proc = await asyncio.create_subprocess_exec(*ssh_args, stderr=stderr)
    except Exception as exc:
        logger.debug(
            "could not spawn ssh to check controlmaster for jumphost: %s: %s",
            jumphost,
            exc,
        )
        raise

    logger.debug("spawned ssh to check controlmaster for jumphost: %s", jumphost)

    try:
        await proc.wait()
    except:
        # if we get cancelled while waiting, first finish waiting to
        # prevent dead processes hanging around.
        await asyncio.shield(proc.wait())
        raise

    if proc.returncode != 0:
        logger.debug("no controlmaster connection available for jumphost: %s", jumphost)
        return None

    logger.debug("reusing controlmaster connection for jumphost: %s", jumphost)

    try:
        async with connect_ssh(args, jumphost, target) as (proc, stdio):
            return stdio, proc, jumphost
    except:
        return None


async def connect_jumphost_direct(args, jumphost, target, socketdir):
    result = await connect_direct_one(args, jumphost, SSH_PORT)
    if result is None:
        logger.debug("could not connect to jump host: %s", jumphost)
        return None
    sock, addr = result

    logger.debug("connection established with jump host: %s (%s)", addr[3], addr[4][0])

    net_sock = sock
    pass_path = os.path.join(socketdir, make_socket_hash(jumphost, addr[4][0]))
    proxy_command = "{}{}{}{} forward-socket-fd {} {}".format(
        args.self_path,
        " -p" if args.use_fdpass else " ",
        " -q" if args.quiet else " ",
        " -v" if args.verbose else " ",
        jumphost,
        pass_path,
    )
    proxy_args = [f"-oproxycommand={proxy_command}"]
    if args.use_fdpass:
        proxy_args.append("-oproxyusefdpass=yes")

    try:
        with passthrough_socket(pass_path) as pass_sock:
            async with connect_ssh(args, jumphost, target, proxy_args) as (proc, stdio):
                loop = asyncio.get_running_loop()

                logger.debug(
                    "waiting for connection on passthrough socket: %s", jumphost
                )

                try:
                    conn_sock, _ = await asyncio.wait_for(
                        loop.sock_accept(pass_sock), SOCKET_PROXY_ACCEPT_TIMEOUT
                    )
                except TimeoutError:
                    logger.debug(
                        "did not receive connection on passthrough socket: %s: operation timed out",
                        hostname,
                    )
                    raise
                except OSError as exc:
                    logger.debug(
                        "did not receive connection on passthrough socket: %s: %s",
                        hostname,
                        exc.strerror,
                    )
                    raise

                logger.debug("received connection on passthrough socket: %s", jumphost)

                try:
                    await asyncio.wait_for(
                        sock_send_fds(conn_sock, [b"\0"], [net_sock.fileno()]),
                        SOCKET_PROXY_SEND_FD_TIMEOUT,
                    )
                except TimeoutError:
                    logger.debug(
                        "could not send network fd for jumphost to socket: %s: operation timed out",
                        hostname,
                    )
                    raise
                except OSError as exc:
                    logger.debug(
                        "could not send network fd for jumphost to socket: %s: %s",
                        hostname,
                        exc.strerror,
                    )
                    raise
                finally:
                    conn_sock.close()

                logger.debug("sent network fd for jumphost socket: %s", jumphost)

                return stdio, addr, proc

    except:
        return None


async def connect_jumphost_indirect(args, jumphost, target):
    try:
        async with connect_ssh(args, jumphost, target) as (proc, stdio):
            return stdio, proc, jumphost
    except:
        return None


async def jumphosts_controlmaster(args):
    jumphosts = args.jump_hosts
    targets = []
    targets.append(args.hostname)
    if args.alt_names is not None and args.jump_altnames:
        targets.extend(args.alt_names)
    logger.debug(
        "spawning controlmaster connections for jumphosts: %s", ", ".join(jumphosts)
    )

    tasks = [
        create_subtask(connect_jumphost_controlmaster(args, jumphost, target))
        for jumphost in jumphosts
        for target in targets
    ]

    return await wait_first_nonempty(tasks)


async def jumphosts_direct(args):
    jumphosts = args.jump_hosts
    targets = []
    targets.append(args.hostname)
    if args.alt_names is not None and args.jump_altnames:
        targets.extend(args.alt_names)
    logger.debug("spawning connections for jumphosts: %s", ", ".join(jumphosts))
    with tempfile.TemporaryDirectory(prefix="ssh-multi-proxy.") as tmpdir:
        tasks = [
            create_subtask(connect_jumphost_direct(args, jumphost, target, tmpdir))
            for jumphost in jumphosts
            for target in targets
        ]

        return await wait_first_nonempty(tasks)


async def jumphosts_indirect(args):
    jumphosts = args.jump_hosts
    targets = []
    targets.append(args.hostname)
    if args.alt_names is not None and args.jump_altnames:
        targets.extend(args.alt_names)
    logger.debug(
        "spawning indirect connections for jumphosts: %s", ", ".join(jumphosts)
    )

    tasks = [
        create_subtask(connect_jumphost_indirect(args, jumphost, target))
        for jumphost in jumphosts
        for target in targets
    ]

    return await wait_first_nonempty(tasks)


class socketproxy:
    def __init__(self, fd):
        os.set_blocking(fd, False)
        self.fd = fd

    def fileno(self):
        return self.fd

    def send(self, data):
        return os.write(self.fd, data)

    def recv(self, sz):
        return os.read(self.fd, sz)


async def proxy_data(src, dest):
    BUF_SIZE = 1024
    loop = asyncio.get_running_loop()
    while True:
        data = await loop.sock_recv(src, BUF_SIZE)
        if not data:
            return
        await loop.sock_sendall(dest, data)


async def connect_main(args):
    sock = None
    addr = None
    proc = None

    fallthrough = False

    if args.direct_connect:
        result = await connect_direct(args)
        if result is None:
            logger.info("could not directly connect to %s", args.hostname)
        else:
            sock, addr = result
            logger.info("directly connected to %s (%s)", addr[3], addr[4][0])
    else:
        logger.info("skipping direct connection to %s", args.hostname)

    if sock is None and args.jump_hosts is not None:
        if "master" in args.jump_indirection:
            result = await jumphosts_controlmaster(args)
            if result is None:
                logger.info("could not connect to jump hosts via control master")
            else:
                sock, proc, host = result
                logger.info("connected to jump host via control master: %s", host)
        else:
            logger.info("skipping connection to jump hosts using control master")

    if sock is None and args.jump_hosts is not None:
        if "direct" in args.jump_indirection:
            result = await jumphosts_direct(args)
            if result is None:
                logger.info("could not connect directly to jump hosts")
                fallthrough = True
            else:
                sock, addr, proc = result
                logger.info(
                    "directly connected to jump host %s (%s)", addr[3], addr[4][0]
                )
        else:
            logger.info("skipping direct connection to jump hosts")

    if sock is None and args.jump_hosts is not None:
        if "indirect" in args.jump_indirection:
            # if calling ssh recurses into this script, then we should
            # avoid child instances trying to connect directly to the
            # primary (non-alternative) hostnames of the jump hosts
            # provided in our command line, as we've tried that and
            # it's failed.
            if fallthrough:
                os.putenv(ENV_SKIP_FIRST_DIRECT, "1")
            result = await jumphosts_indirect(args)
            if result is None:
                logger.info("could not connect indirectly to jump hosts")
            else:
                sock, proc, host = result
                logger.info("indirectly connected to jump host %s", host)
        else:
            logger.info("skipping indirect connection to jump hosts")

    if sock is None:
        logger.error("no connection methods remaining for host: %s", args.hostname)
        return 1

    tasks = []

    if args.use_fdpass:
        ch = b"\23" if proc is not None and args.child_linger else b"\0"
        stdout = socket.socket(fileno=sys.stdout.fileno())
        stdout.setblocking(False)
        try:
            await asyncio.wait_for(
                sock_send_fds(stdout, [ch], [sock.fileno()]),
                SSH_PROXY_FD_SEND_TIMEOUT,
            )
        except TimeoutError:
            logger.error("could not send network fd to stdout: operation timed out")
            return 1
        except OSError as exc:
            logger.error("could not send network fd to stdout: %s", exc.strerror)
            return 1
    else:
        sock.setblocking(False)
        tasks.extend(
            map(
                lambda t: create_subtask(t),
                [
                    proxy_data(socketproxy(sys.stdin.fileno()), sock),
                    proxy_data(sock, socketproxy(sys.stdout.fileno())),
                ],
            )
        )

    if proc and args.child_linger:

        async def wrap_proc(proc):
            try:
                return await proc.wait()
            except asyncio.CancelledError:
                proc.terminate()

        tasks.append(create_subtask(wrap_proc(proc)))

    ret = 0

    if tasks:
        done, _ = await asyncio.wait(tasks)
        if proc:
            if proc.returncode != 0:
                logger.error("subprocess exited with error: %d", proc.returncode)
                return 1
        for task in done:
            exc = task.exception()
            if exc is not None:
                logger.error("task raised exception: %s", exc)
                ret = 1

    return ret


async def forward_socket_main(args):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.setblocking(False)

    try:
        await loop.sock_connect(sock, args.socket_path)
    except OSError as exc:
        logger.debug(
            "could not connect: %s: %s: %s",
            args.hostname,
            args.socket_path,
            exc.strerror,
        )
        return 1

    try:
        _, fds, _, _ = await asyncio.wait_for(
            sock_recv_fds(sock, 1, 1), SOCKET_PROXY_RECV_FD_TIMEOUT
        )
    except TimeoutError:
        logger.debug("could not receive fd: %s: operation timed out", args.hostname)
        return 1
    except OSError as exc:
        logger.debug("could not receive fd: %s: %s", args.hostname, exc.strerror)
        return 1

    sock.close()

    if not fds:
        logger.debug("did not receive fds on socket: %s", args.hostname)
        return 1

    if args.use_fdpass:
        try:
            stdout = socket.socket(fileno=sys.stdout.fileno())
            stdout.setblocking(False)
            await asyncio.wait_for(
                sock_send_fds(stdout, [b"\0"], fds),
                SSH_PROXY_FD_SEND_TIMEOUT,
            )
        except TimeoutError:
            logger.debug(
                "could not send file descriptor: %s: operation timed out", args.hostname
            )
            return 1
        except OSError as exc:
            logger.debug(
                "could not send file descriptor: %s: %s", args.hostname, exc.strerror
            )
            return 1
        else:
            return 0

    sock = socket.socket(fileno=fds[0])
    sock.setblocking(False)

    tasks = map(
        lambda t: create_subtask(t),
        [
            proxy_data(socketproxy(sys.stdin.fileno()), sock),
            proxy_data(sock, socketproxy(sys.stdout.fileno())),
        ],
    )

    done, _ = await asyncio.wait(tasks)

    ret = 0

    for task in done:
        exc = task.exception()
        if exc is not None:
            logger.error("could not proxy data: %s", exc)
            ret = 1

    return ret


async def main_coro(args):
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, task.cancel)
    loop.add_signal_handler(signal.SIGTERM, task.cancel)

    try:
        ret = await args.main(args)
    except asyncio.CancelledError:
        logger.debug("exiting on signal")
        return 0

    return ret


def parse_indirection_argument(arg):
    modes = ["master", "direct", "indirect"]

    if arg == "all":
        return modes
    elif arg == "nomaster":
        return ["direct", "indirect"]

    flags = arg.split(",")
    for flag in flags:
        if flag not in modes:
            raise argparse.ArgumentTypeError(f"invalid indirection flag: {flag}")

    return flags


def main():
    parser = argparse.ArgumentParser(
        prog="ssh-multi-proxy",
        description="Automatically select the fastest SSH jump host",
    )
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "-v", "--verbose", action="store_true", help="Print additional log messages"
    )
    log_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress informational messages"
    )
    parser.add_argument(
        "-S", "--ssh-path", default="ssh", help="Path to SSH client program"
    )
    parser.add_argument(
        "-P",
        "--self-path",
        default=sys.argv[0],
        help="Path to ssh-multi-proxy (for child processes)",
    )
    parser.add_argument(
        "-D",
        "--fallback-delay",
        help="Fallback delay for happy eyeballs (milliseconds)",
        type=int,
        default=300,
    )
    parser.add_argument(
        "-p",
        "--proxy-fd",
        action="store_true",
        default=False,
        dest="use_fdpass",
        help="Use ProxyUseFdpass with the OpenSSH client instead of proxying data directly",
    )

    subparsers = parser.add_subparsers(required=True, dest="command")
    connect_parser = subparsers.add_parser(
        "connect",
        help="Connect to remote host and proxy data or pass socket",
    )
    connect_parser.set_defaults(main=connect_main)
    connect_parser.add_argument(
        "-n",
        "--no-direct",
        dest="direct_connect",
        action="store_false",
        help="Skip connecting to the remote host directly, always use the jump hosts",
    )
    connect_parser.add_argument(
        "-a",
        "--alt-name",
        dest="alt_names",
        metavar="HOST",
        action="append",
        help="Additional hostnames to try connecting to (for multi-homed hosts)",
    )
    connect_parser.add_argument(
        "-k",
        "--skip-private-ipv4",
        dest="skip_private_ipv4",
        action="store_true",
        help="Skip private IPv4 addresses when connecting to remote hosts",
    )

    connect_parser.add_argument(
        "-j",
        "--jump-host",
        dest="jump_hosts",
        action="append",
        metavar="HOST",
        help="Add HOST to the list of jump hosts to be tried in parallel",
    )
    connect_parser.add_argument(
        "-i",
        "--jump-indirection",
        metavar="all|nomaster|{master,direct,indirect}",
        default="direct",
        type=parse_indirection_argument,
        help="Select indirection mode: using ControlMaster socket, only directly, only through SSH if direct connections fail",
    )
    connect_parser.add_argument(
        "-x",
        "--jump-alternatives",
        dest="jump_altnames",
        action="store_true",
        help="Also to connect to alternative hostnames through jump hosts",
    )
    connect_parser.add_argument(
        "-u",
        "--proxy-username",
        metavar="USER",
        help="Login name for jump hosts",
    )

    connect_parser.add_argument(
        "-w",
        "--wait-readiness",
        action="store_true",
        default=False,
        dest="wait_readiness",
        help="Wait for ssh client to signal forwarding readiness",
    )
    connect_parser.add_argument(
        "-l",
        "--linger",
        action="store_true",
        default=False,
        dest="child_linger",
        help="Do not exit immediately after passing proxy fd to ssh client if a child process has been spawned",
    )

    connect_parser.add_argument(
        "-c",
        "--control-path",
        default="~/.ssh/controlmasters/%C.sock",
        help="Path to the control master socket for the jump hosts",
    )
    connect_parser.add_argument(
        "-t",
        "--control-persist",
        default="10m",
        help="Persistence duration for spawned control master connections",
    )

    connect_parser.add_argument("hostname", metavar="HOSTNAME", help="Remote hostname")
    connect_parser.add_argument("port", metavar="PORT", type=int, help="Remote port")

    forward_parser = subparsers.add_parser(
        "forward-socket-fd",
        help="Retrieve file descriptor for remote host [internal command]",
    )
    forward_parser.set_defaults(main=forward_socket_main)
    forward_parser.add_argument(
        "hostname", metavar="HOSTNAME", help="Remote hostname (for logging purposes)"
    )
    forward_parser.add_argument(
        "socket_path",
        metavar="SOCKET_PATH",
        help="Path to socket on which the file descriptor can be received",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif not args.quiet and ENV_SUPPRESS_LOGGING not in os.environ:
        logger.setLevel(logging.INFO)

    sys.exit(asyncio.run(main_coro(args)))


if __name__ == "__main__":
    main()

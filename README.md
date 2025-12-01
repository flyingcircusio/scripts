# Scripts

An assorted collection of various utility scripts.

## Script READMEs

### ssh-multi-proxy

`ssh-multi-proxy` is a Python script which acts as a smart proxy
command for SSH. The design goal is to connect to the named remote
host by any means necessary without the operator having to consciously
think about what path they might need to take to get there, depending
on the local environment.

The script can successively attempt to connect to a remote host
directly (with happy eyeballs for fast fallback from IPv6 to IPv4),
and if that fails it can fall back to connecting to jump hosts through
a variety of other methods, including direct connections, existing
client multiplexer sockets, or spawning separate SSH commands as child
processes.

Configuration example:

```
CanonicalizeHostname always
Host *
CanonialDomains example.com


# Hosts are only accessible via bastion host
Host switch1.example.com switch2.example.com
Tag proxyjump

# Hostname wildcard for management network, also accessed via bastion host
Host *.mgm.example.com
Tag proxyjump

# Fallback for all other hosts under example.com
Host *.example.com
Tag direct


# Tags (OpenSSH 9.4+) used for grouping configuration

# Connect to hosts directly, or if that fails (e.g. IPv4-only network) 
# use the bastion host as a jump host.
Match tagged="direct"
ProxyUseFdpass yes
ProxyCommand ssh-multi-proxy -p connect -i master,direct -j bastion.example.com %h %p

# Don't connect directly, always use the bastion host as a jump host.
Match tagged="proxyjump"
ProxyUseFdpass yes
ProxyCommand ssh-multi-proxy -p connect -ni all -j bastion.example.com %h %p
```

### git-tree-sync

This is a git command script which is intended for managing dev
checkouts of git repositories on remote machines using native git
tooling. The intitution is that the script creates a snapshot of the
current working tree state similar to `git stash`, and then pushes
that snapshot to the remote machine and checks it out. The history of
working tree states pushed to each configured remote host is recorded
in a reflog, and there is also a safety belt which tracks which branch
was most recently pushed to, to avoid inadvertently pushing a
different branch by accident.

An example of usage (assuming `git-tree-sync` is available in PATH):

```
$ cd path/to/git/repo
$ git tree-sync add remotehost   # add remotehost as sync target
$ # hack hack hack
$ git tree-sync sync remotehost  # sync working tree to remotehost
```

It's recommended to set an alias for the `sync` subcommand to save on
typing, e.g. `git config --global alias.ts 'tree-sync sync'`.

### mosh tools

`mosh-dualstack-proxy` is a wrapper around the mosh binaries which
dynamically proxies packets between the client and server over IPv4 or
IPv6 depending on which path currently works. This is useful for
long-lived sessions which should be kept alive while moving between
different networks, which may or may not provide IPv4 or IPv6
connectivity. This script only works with Linux remote hosts, and
assumes that `ip(8)` is in the remote PATH.

`mosh-tunnel` tunnels mosh over SSH. This allows using mosh to log
into machines which do not have the UDP ports for mosh open in their
firewalls or logging into machines which are only accessible via jump
host. This can be combined with a VPN tunnel for maintaining
interactive sessions with remote machines over an unstable or jittery
internet connection – by connecting to the VPN server through the
tunnel and using it as a jump host to connect to further hosts, the
VPN tunnel buffers packets while mosh by default provides interactive
typing prediction. This script requires the `asyncio_dgram` Python
library.

Both scripts support using `nix-shell` to execute the mosh server
instead of relying on it being available in PATH on the remote host.

## License

These scripts are released under the terms of the MIT license.

```
Copyright (c) 2025 Flying Circus Internet Operations GmbH

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

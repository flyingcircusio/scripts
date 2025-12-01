#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from contextlib import contextmanager

logging.basicConfig(format="git tree-sync: %(message)s")
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def die(msg):
    log.error(f"fatal: {msg}")
    sys.exit(1)


def log_cmd_err(err: subprocess.CalledProcessError):
    log.error("command exited with error: {}".format(" ".join(err.cmd)))


@contextmanager
def temporary_index(git_dir):
    index = NamedTemporaryFile(
        prefix="index.tree-sync.", dir=git_dir, delete_on_close=False
    )
    # git plumbing uses atomic renames to manipulate the index file,
    # and it does not like index files which exist but are empty. so we
    # need to hack around this a bit.
    with index:
        index.close()
        os.unlink(index.name)
        yield index


class Git(object):
    default_options = dict(stdout=subprocess.PIPE, check=True)

    def __init__(self, args):
        self.git_flags = {}
        self.git_path = args.git_path
        self.extra_env = {}

        # set up fallback git identity if none set
        self.git_flags["-c"] = "user.useconfigonly=yes"
        ret, _ = self.__run__(
            "var", *["GIT_COMMITTER_IDENT"], check=False, stderr=subprocess.DEVNULL
        )
        if ret != 0:
            self.extra_env.update(
                {
                    "GIT_AUTHOR_NAME": "git tree-sync",
                    "GIT_AUTHOR_EMAIL": "git@tree-sync",
                    "GIT_COMMITTER_NAME": "git tree-sync",
                    "GIT_COMMITTER_EMAIL": "git@tree-sync",
                }
            )
        del self.git_flags["-c"]

    def chdir(self, path):
        self.git_flags["-C"] = path

    def set_ssh_command(self, command, args):
        self.extra_env["GIT_SSH_COMMAND"] = "{} {}".format(command, " ".join(args))

    def __run__(self, subcmd, *args, **kw):
        cmd = [self.git_path]
        for flag, value in self.git_flags.items():
            cmd.extend([flag, value])
        cmd.append(subcmd)
        cmd.extend(args)

        kw = kw.copy()

        strip = True
        if "strip" in kw:
            strip = kw["strip"]
            del kw["strip"]
        if strip:
            kw["text"] = True
        if "env" not in kw:
            kw["env"] = os.environ.copy()
        kw["env"].update(self.extra_env)

        options = self.default_options.copy()
        options.update(kw)

        log.debug("running command: {}".format(" ".join(cmd)))
        try:
            proc = subprocess.run(cmd, **options)
        except subprocess.CalledProcessError as e:
            log.debug(f"command exited with error {e.returncode}")
            raise
        log.debug(f"command exited with code {proc.returncode}")

        data = proc.stdout
        if strip:
            data = data.strip()

        if "check" in options and options["check"]:
            return data
        else:
            return proc.returncode, data

    def __getattr__(self, subcmd):
        subcmd = subcmd.replace("_", "-")

        def callable(*args, **kw):
            return self.__run__(subcmd, *args, **kw)

        return callable


class Config(object):
    args: argparse.Namespace
    git: Git
    basename: str

    SCOPE_OPTION = "--local"
    CONFIG_BASE = "treesync"
    REF_BASE = ["refs", "treesync"]

    def __init__(self, args, git, basename):
        self.args = args
        self.git = git
        self.basename = basename
        self.ssh_args = []

        try:
            self.split_worktrees = self.get(
                "extensions.worktreeConfig",
                isbool=True,
                default=False,
                scope_option=None,
                exact_key=True,
            )

            config_ssh_args = self.get(
                "treesync.extraSshArgs", default="", scope_option=None, exact_key=True
            )
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die(f"git config exited with error: {e.returncode}")

        if self.split_worktrees:
            self.SCOPE_OPTION = "--worktree"

        if config_ssh_args:
            self.ssh_args.extend(config_ssh_args.split())
        if hasattr(args, "proxy_jump") and args.proxy_jump:
            self.ssh_args.extend(["-J", args.proxy_jump])

        self.git.set_ssh_command(args.ssh_path, self.ssh_args)

    def ssh(self, hostname, *args):
        cmd = [self.args.ssh_path]
        cmd.extend(self.ssh_args)
        cmd.extend([hostname, "--"])
        cmd.extend(args)

        log.debug("running command: {}".format(" ".join(cmd)))
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            log.debug(f"command exited with code {e.returncode}")
            raise
        log.debug("command exited successfully")

    def get(
        self,
        key,
        check=True,
        isbool=False,
        default=None,
        exact_key=False,
        scope_option=SCOPE_OPTION,
    ):
        if not exact_key:
            key = ".".join([self.CONFIG_BASE, self.args.hostname, key])

        if isbool and default is not None:
            default = str(default).lower()

        args = ["--get"]
        if scope_option:
            args.append(scope_option)
        if isbool:
            args.append("--type=bool")
        if default is not None:
            args.append(f"--default={default}")
        args.append(key)

        data = self.git.config(*args, check=check)
        if not check:
            ret, data = data

        if isbool:
            if data == "true":
                data = True
            elif data == "false":
                data = False
            else:
                die(f"git config --get --type=bool returned non-boolean data: {data}")

        if not check:
            return ret, data
        else:
            return data

    def set(self, key, value, scope_option=SCOPE_OPTION):
        key = ".".join([self.CONFIG_BASE, self.args.hostname, key])

        if isinstance(value, bool):
            value = str(value).lower()

        args = []
        if scope_option:
            args.append(scope_option)
        args.extend([key, value])

        self.git.config(*args)

    def remove(self):
        section = ".".join([self.CONFIG_BASE, self.args.hostname])
        git.config(self.SCOPE_OPTION, "--remove-section", section)

    def ref_path(self, slug):
        path = self.REF_BASE.copy()
        if self.split_worktrees:
            path.append(self.basename)
        path.append(args.hostname)
        path.append(slug)
        return "/".join(path)


def add_main(args, git, cfg):
    ret, _ = cfg.get("hostname", check=False)
    if ret == 0:
        die(f"host {args.hostname} already exist in the configuration")
    elif ret > 1:
        die(f"unexpected error from git config {ret}")

    realname = args.hostname
    if args.real_hostname is not None:
        realname = args.real_hostname

    if args.do_init:
        remote_path = cfg.basename
        if args.remote_path:
            remote_path = args.remote_path

        remote_git = "git"
        if args.remote_git_command:
            remote_git = args.remote_git_command

        try:
            cfg.ssh(realname, remote_git, "init", "-b", "main", remote_path)
            cfg.ssh(
                realname,
                remote_git,
                "-C",
                remote_path,
                "config",
                "receive.denyCurrentBranch",
                "updateInstead",
            )
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die("could not create repository on remote host")

    try:
        cfg.set("hostname", realname)
        if not args.do_branch_lock:
            cfg.set("branchLock", False)
        if not args.do_compress_history:
            cfg.set("compressHistory", False)
        if args.remote_path:
            cfg.set("remotePath", args.remote_path)
        if args.remote_git_command:
            cfg.set("remoteGitCommand", args.remote_git_command)
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        try:
            cfg.remove()
            log.error("rolled back configuration")
        except subprocess.CalledProcessError as e2:
            if e2.returncode != 1:
                log.error("could not clean remote configuration")
                log_cmd_err(e2)
        finally:
            if args.do_init:
                log.error(
                    "warning: git repository created on remote host but not configured locally"
                )
            sys.exit(1)

    if not args.do_init:
        log.warning(
            f"warning: host {args.hostname} added to configuration without creating git repository on remote host"
        )


def clean_main(args, git, cfg):
    ret, realname = cfg.get("hostname", check=False)
    if ret != 0:
        die(f"host {args.hostname} does not exist in configuration")

    try:
        remote_path = cfg.get("remotePath", default=cfg.basename)
        remote_git = cfg.get("remoteGitCommand", default="git")
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        die(f"could not load configuration for {args.hostname}")

    try:
        cargs = [remote_git, "-C", remote_path, "clean", "-d", "-f"]
        if args.clean_ignored:
            cargs.append("-x")
        if args.dry_run:
            cargs.append("-n")
        cfg.ssh(realname, *cargs)

        if not args.dry_run:
            cfg.ssh(realname, remote_git, "-C", remote_path, "checkout", "--", ".")
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        die("could not clean repository on remote host")


def remove_main(args, git, cfg):
    ret, realname = cfg.get("hostname", check=False)
    if ret != 0:
        die(f"host {args.hostname} does not exist in configuration")

    try:
        remote_path = cfg.get("remotePath", default=cfg.basename)
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        die(f"could not load configuration for {args.hostname}")

    # XXX: remove refs which might be sitting around? add a cli option
    # to make this toggleable?

    try:
        cfg.remove()
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        die(f"could not remove configuration for {args.hostname}")

    log.info(f"host {realname} removed from configuration")
    log.info(
        f"clean up remaining files on remote host with: {args.ssh_path} {realname} -- rm -rf {remote_path}"
    )


def sync_main(args, git, cfg):
    ret, hostname = cfg.get("hostname", check=False)
    if ret != 0:
        die(f"host {args.hostname} does not exist in configuration")

    # load configuration
    try:
        remote_path = cfg.get("remotePath", default=cfg.basename)
        remote_git_command = cfg.get("remoteGitCommand", default="")
        remote_branch = cfg.get("remoteBranch", default="main")
        cfg_branch_lock = cfg.get("branchLock", isbool=True, default=True)
        cfg_compress = cfg.get("compressHistory", isbool=True, default=True)
    except subprocess.CalledProcessError as e:
        log_cmd_err(e)
        die(f"could not load configuration for {args.hostname}")

    include_history = not cfg_compress
    if args.compress_history:
        include_history = False
    if args.no_compress_history:
        include_history = True

    # read data from the repository
    git.update_index("--refresh", "-q", check=False)
    ret, head_commit = git.rev_parse("--quiet", "--verify", "HEAD", check=False)
    if ret != 0:
        die("empty repository (no commits yet)")

    ret, head_branch = git.symbolic_ref("--quiet", "HEAD", check=False)
    if ret != 0:
        # detached HEAD state
        head_branch = None
    else:
        head_branch_pretty = head_branch.removeprefix("refs/heads/")

    ret, head_tree = git.rev_parse("--quiet", "--verify", "HEAD:", check=False)
    if ret != 0:
        die("could not read HEAD tree object from repository")
    ret, git_dir = git.rev_parse("--path-format=absolute", "--git-dir", check=False)
    if ret != 0:
        die("could not read git directory from repository")

    remote_tree_ref = cfg.ref_path("head") + ":"
    ret, remote_tree = git.rev_parse(
        "--quiet", "--verify", remote_tree_ref, check=False
    )
    if ret != 0:
        # first run: the host head ref doesn't point to a commit with
        # a tree yet.
        remote_tree = None

    # read recorded locked branch
    if cfg_branch_lock:
        ret, locked_branch = git.symbolic_ref(
            "--quiet", cfg.ref_path("branch"), check=False
        )
        if ret != 0:
            # locked branch not yet recorded (first run, detached head, etc)
            locked_branch = None
        else:
            locked_branch_pretty = locked_branch.removeprefix("refs/heads/")

        if (
            not args.release_lock
            and locked_branch is not None
            and locked_branch != head_branch
        ):
            msg = "refusing to sync: current "
            if head_branch:
                msg += f"branch is {head_branch_pretty} "
            else:
                msg += "head is detached "
            msg += f"but {args.hostname} last synced with {locked_branch_pretty} "
            msg += "(use -l to override)"
            die(msg)

    # starting at the HEAD tree, read changes in the current working
    # tree
    combined_tree = head_tree
    index_tree = None
    working_tree = None
    untracked_tree = None

    # record staged changes in the index
    ret, _ = git.diff_index(
        "--quiet", "--cached", "HEAD", "--ignore-submodules", check=False
    )
    if ret != 0:
        try:
            index_tree = git.write_tree()
            combined_tree = index_tree
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die("could not write tree for current index")

    # record unstaged changes in the working tree
    ret, _ = git.diff_files("--quiet", "--ignore-submodules", check=False)
    if ret != 0:
        try:
            with temporary_index(git_dir) as tmpindex:
                git.read_tree(f"--index-output={tmpindex.name}", "-m", combined_tree)

                cmdenv = os.environ.copy()
                cmdenv["GIT_INDEX_FILE"] = tmpindex.name
                working_names = git.diff_index(
                    "--name-only", "-z", "HEAD", env=cmdenv, strip=False
                )
                git.update_index(
                    "-z",
                    "--add",
                    "--remove",
                    "--stdin",
                    env=cmdenv,
                    strip=False,
                    input=working_names,
                )
                working_tree = git.write_tree(env=cmdenv)
                combined_tree = working_tree
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die("could not write tree for current working tree")

    # record the current untracked files in the working tree
    if args.sync_untracked:
        uargs = ["-o", "-z"]
        if not args.include_ignored:
            uargs.append("--exclude-standard")
        try:
            untracked_files = git.ls_files(*uargs, strip=False)
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die("could not read untracked files in working tree")

        if untracked_files:
            try:
                with temporary_index(git_dir) as tmpindex:
                    git.read_tree(f"--index-output={tmpindex.name}", combined_tree)

                    cmdenv = os.environ.copy()
                    cmdenv["GIT_INDEX_FILE"] = tmpindex.name
                    git.update_index(
                        "-z",
                        "--add",
                        "--remove",
                        "--stdin",
                        env=cmdenv,
                        strip=False,
                        input=untracked_files,
                    )
                    untracked_tree = git.write_tree(env=cmdenv)
                    combined_tree = untracked_tree
            except subprocess.CalledProcessError as e:
                log_cmd_err(e)
                die("could not write tree for untracked files in working tree")

    if remote_tree is None or remote_tree != combined_tree or args.force_sync:
        state_description = "{}: {}".format(
            head_branch_pretty if head_branch else "(no branch)", head_commit
        )

        try:
            if include_history:
                combined_commit = head_commit
            else:
                combined_commit = git.commit_tree(
                    head_tree, input=f"branch state on {state_description}"
                )

            if index_tree:
                combined_commit = git.commit_tree(
                    index_tree,
                    "-p",
                    combined_commit,
                    input=f"index on {state_description}",
                )
            if working_tree:
                combined_commit = git.commit_tree(
                    working_tree,
                    "-p",
                    combined_commit,
                    input=f"working tree on {state_description}",
                )
            if untracked_tree:
                combined_commit = git.commit_tree(
                    untracked_tree,
                    "-p",
                    combined_commit,
                    input=f"untracked files on {state_description}",
                )
        except subprocess.CalledProcessError as e:
            log_cmd_err(e)
            die("could not commit trees to database")

        push_args = ["--force"]
        if not args.verbose and not args.push_verbose:
            push_args.append("--quiet")
        if remote_git_command:
            push_args.append(f"--receive-pack={remote_git_command} receive-pack")
        push_args.extend(
            [
                f"{hostname}:{remote_path}",
                f"{combined_commit}:refs/heads/{remote_branch}",
            ]
        )
        ret, _ = git.push(
            *push_args,
            check=False,
            strip=False,
            stdout=None,
        )
        if ret != 0:
            die("could not push current working tree to remote host")

        if head_branch:
            desc = head_branch_pretty
        else:
            desc = "no branch"
        ret, _ = git.update_ref(
            "--create-reflog",
            "-m",
            f"sync: working tree on {desc}",
            cfg.ref_path("head"),
            combined_commit,
            check=False,
        )
        if ret != 0:
            log_cmd_err(e)
            die("pushed to remote host but could not update local reflog")
    else:
        log.info("remote working tree is up to date")

    if cfg_branch_lock and head_branch is not None and locked_branch != head_branch:
        ret, _ = git.symbolic_ref(
            "-m",
            f"sync: moved to new base branch {head_branch_pretty}",
            cfg.ref_path("branch"),
            head_branch,
            check=False,
        )
        if ret != 0:
            log_cmd_err(e)
            die("could not update branch lock ref")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="git tree-sync",
        description="Use git to synchronise the working tree with a remote host",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Print additional log messages",
    )
    parser.add_argument(
        "-G",
        "--git-path",
        default="git",
        metavar="PATH",
        help="Path to git executable",
    )
    parser.add_argument(
        "-S",
        "--ssh-path",
        default="ssh",
        metavar="PATH",
        help="Path to ssh client program",
    )

    subparsers = parser.add_subparsers(required=True, dest="command")
    add_parser = subparsers.add_parser(
        "add",
        help="Add a new remote host to be synchronised from this worktree",
    )
    add_parser.set_defaults(main=add_main)
    add_parser.add_argument(
        "-g",
        "--remote-git-command",
        metavar="COMMAND",
        help="Execute COMMAND for invoking git on the remote server",
    )
    add_parser.add_argument(
        "-p",
        "--remote-path",
        metavar="PATH",
        help="Create the git repository under PATH on the remote host (default: basename of the current working tree)",
    )
    add_parser.add_argument(
        "-a",
        "--alias-for",
        metavar="TARGET",
        dest="real_hostname",
        help="Record HOSTNAME as an alias for TARGET and connect to TARGET over ssh instead",
    )
    add_parser.add_argument(
        "-n",
        "--no-init",
        action="store_false",
        dest="do_init",
        default=True,
        help="Skip setting up the remote git repository, add the local configuration only",
    )
    add_parser.add_argument(
        "-J",
        "--proxy-jump",
        metavar="SPEC",
        help="Use proxy jump spec SPEC for connecting to the remote host (warning: not recorded in the configuration)",
    )
    add_parser.add_argument(
        "-L",
        "--no-branch-lock",
        action="store_false",
        dest="do_branch_lock",
        default=True,
        help="Do not create a ref which tracks which branch the remote host was last synchronised from",
    )
    add_parser.add_argument(
        "-C",
        "--no-compress-history",
        action="store_false",
        dest="do_compress_history",
        default=True,
        help="Do not compress commit history when synchronising with remote host by default",
    )
    add_parser.add_argument(
        "hostname",
        metavar="HOSTNAME",
        help="Host to configure synchronisation with and add to configuration ",
    )

    # git-reflog wrapper?

    clean_parser = subparsers.add_parser(
        "clean",
        help="Clean untracked changes and files in the checkout on the remote host",
    )
    clean_parser.set_defaults(main=clean_main)
    clean_parser.add_argument(
        "-x",
        "--clean-ignored",
        action="store_true",
        default=False,
        help="Pass the -x flag to git-clean",
    )
    clean_parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        default=False,
        help="Pass the -n flag to git-clean",
    )
    clean_parser.add_argument(
        "hostname", metavar="HOSTNAME", help="Host whose checkout should be cleaned"
    )

    remove_parser = subparsers.add_parser(
        "remove",
        help="Remove an existing remote host from the configuration",
    )
    remove_parser.set_defaults(main=remove_main)
    remove_parser.add_argument(
        "hostname",
        metavar="HOSTNAME",
        help="Host to remove from the configuration configuration",
    )

    sync_parser = subparsers.add_parser(
        "sync", help="Sync the current working tree to the remote host"
    )
    sync_parser.set_defaults(main=sync_main)
    compress_group = sync_parser.add_mutually_exclusive_group()
    compress_group.add_argument(
        "-c",
        "--compress-history",
        action="store_true",
        default=False,
        help="Override configuration and upload full uncompressed history",
    )
    compress_group.add_argument(
        "-C",
        "--no-compress-history",
        action="store_true",
        default=False,
        help="Override configuration and compress history before uploading",
    )
    tracked_group = sync_parser.add_mutually_exclusive_group()
    tracked_group.add_argument(
        "-U",
        "--no-untracked-files",
        action="store_false",
        dest="sync_untracked",
        default=True,
        help="Do not sync untracked files in the current working tree",
    )
    tracked_group.add_argument(
        "-i",
        "--include-ignored",
        action="store_true",
        default=False,
        help="Also sync files which would be ignored by .gitignore",
    )
    sync_parser.add_argument(
        "-l",
        "--release-lock",
        action="store_true",
        default=False,
        help="Sync even if the working tree is on a different branch from the previous sync",
    )
    sync_parser.add_argument(
        "-f",
        "--force-sync",
        action="store_true",
        default=False,
        help="Sync working tree with remote host even when working tree has not changed",
    )
    sync_parser.add_argument(
        "-v",
        "--push-verbose",
        action="store_true",
        default=False,
        help="Do not suppress the output from git-push",
    )
    sync_parser.add_argument(
        "hostname",
        metavar="HOSTNAME",
        help="Remote host to which working tree should be synced",
    )
    # XXX: add optional arguments to only sync certain subdirectories
    # of the working tree? or only the changes relative to the base
    # commit of the working tree?

    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    git = Git(args)

    try:
        top_level = git.rev_parse("--show-toplevel")
    except subprocess.CalledProcessError:
        # git has already printed an error message to stderr
        sys.exit(1)
    git.chdir(top_level)

    basename = Path(top_level).name

    cfg = Config(args, git, basename)

    args.main(args, git, cfg)

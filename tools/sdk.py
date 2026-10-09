#!/usr/bin/env python3
"""准备或验证由公开精确提交构成的独立 SDK，不修改其他 SDK。"""
from __future__ import annotations

import argparse
import hashlib
import stat
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import sys

LOCK_PATH = Path(__file__).resolve().parents[1] / "sdk-lock.json"


def git_environment() -> dict:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE"):
        if os.environ.get(name):
            raise ValueError(f"Git 环境不能重定向来源或 alternate 对象：{name}")
    # Every Git command reads the actual locked objects, regardless of caller flags.
    return {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True, env=git_environment())
    if result.returncode:
        raise RuntimeError(f"Git 失败：{' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def read_lock() -> dict:
    lock = json.loads(LOCK_PATH.read_text())
    if set(lock) != {"schema_version", "idf", "lwip"} or lock["schema_version"] != 1:
        raise ValueError("不支持的 SDK 锁文件")
    for name, fields in (("idf", {"repository", "revision"}),
                         ("lwip", {"repository", "revision", "path"})):
        entry = lock[name]
        if set(entry) != fields or not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]):
            raise ValueError(f"{name} 必须锁定完整提交")
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9-]+\.git", entry["repository"]):
            raise ValueError(f"{name} 必须使用明确的公开 GitHub HTTPS 源")
    if lock["lwip"]["path"] != "components/lwip/lwip":
        raise ValueError("lwIP 装配位置与 ESP-IDF 合同不符")
    return lock


def verify_object_bytes(path: Path) -> None:
    """重算独立对象库每个对象的原始 Git OID，不改写或忽略历史内容。"""
    object_format = git(path, "rev-parse", "--show-object-format")
    if object_format not in ("sha1", "sha256"):
        raise ValueError("来源 Git 对象摘要格式不受支持")
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(["git", "-C", str(path), "cat-file", "--batch-all-objects",
                                    "--batch", "--unordered"], stdout=subprocess.PIPE,
                                   stderr=errors, env=git_environment())
        try:
            while True:
                header = process.stdout.readline(1024)
                if not header:
                    break
                fields = header.rstrip(b"\n").split()
                if not header.endswith(b"\n") or len(fields) != 3:
                    raise ValueError(f"来源 Git 对象批处理帧不完整：{path}")
                object_id, kind, raw_size = fields
                if kind not in (b"blob", b"tree", b"commit", b"tag") or not raw_size.isdigit():
                    raise ValueError(f"来源 Git 对象类型或长度无效：{path}")
                size = int(raw_size)
                digest = hashlib.new(object_format, kind + b" " + raw_size + b"\0")
                remaining = size
                while remaining:
                    chunk = process.stdout.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(f"来源 Git 对象原始字节被截断：{path}")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if process.stdout.read(1) != b"\n" or digest.hexdigest().encode() != object_id:
                    raise ValueError(f"来源 Git 对象原始字节与 OID 不符：{path}")
            if process.wait():
                errors.seek(0)
                raise ValueError(f"来源 Git 对象读取失败：{path}\n"
                                 f"{errors.read().decode(errors='replace').strip()}")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
            process.wait()


def verify_tracked_tree(path: Path, source_root: Path, gitlink_overrides: dict, revision: str) -> None:
    """直接以 HEAD 的 Git blob 字节与类型核对源码，不读取 index 的内容提示。"""
    result = subprocess.run(["git", "-C", str(path), "ls-tree", "-r", "-z", revision],
                            check=True, capture_output=True, env=git_environment())
    object_format = git(path, "rev-parse", "--show-object-format")
    if object_format not in ("sha1", "sha256"):
        raise ValueError("来源 Git 对象摘要格式不受支持")
    tree_entries = [entry for entry in result.stdout.split(b"\0") if entry]
    expected_index = set()
    for entry in tree_entries:
        header, name = entry.split(b"\t", 1)
        mode, _, object_id = header.split()
        expected_index.add((mode, object_id, b"0", name))
    index = subprocess.run(["git", "-C", str(path), "ls-files", "--stage", "-z"],
                           check=True, capture_output=True, env=git_environment())
    actual_index = set()
    for entry in index.stdout.split(b"\0"):
        if entry:
            header, name = entry.split(b"\t", 1)
            mode, object_id, stage = header.split()
            actual_index.add((mode, object_id, stage, name))
    if actual_index != expected_index:
        raise ValueError(f"来源索引与锁定 HEAD 树不符：{path}")
    checked_directories = {path}
    for entry in tree_entries:
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = header.split()
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or any(piece in (".", "..") for piece in relative.parts):
            raise ValueError("来源 HEAD 路径不能越出 checkout")
        file = path / relative
        parent = file.parent
        while parent not in checked_directories:
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ValueError(f"来源 tracked 父目录类型与 HEAD 不符：{parent}")
            checked_directories.add(parent)
            parent = parent.parent
        actual = file.lstat()
        if mode == b"160000" and kind == b"commit":
            if not stat.S_ISDIR(actual.st_mode):
                raise ValueError(f"来源 gitlink 目录类型与 HEAD 不符：{file}")
            expected = gitlink_overrides.get(file.relative_to(source_root).as_posix(),
                                             object_id.decode("ascii"))
            if git(file, "rev-parse", "HEAD") != expected:
                raise ValueError(f"来源 gitlink 提交与锁定 HEAD 不符：{file}")
            verify_complete_repository(file, source_root=source_root,
                                       gitlink_overrides=gitlink_overrides, revision=expected)
            continue
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise ValueError(f"来源 HEAD 包含不支持的文件类型：{file}")
        if mode == b"120000":
            if not stat.S_ISLNK(actual.st_mode):
                raise ValueError(f"来源 tracked 符号链接类型与 HEAD 不符：{file}")
            content = os.fsencode(os.readlink(file))
            digest = hashlib.new(object_format, b"blob " + str(len(content)).encode() + b"\0")
            digest.update(content)
        else:
            if (not stat.S_ISREG(actual.st_mode)
                    or bool(actual.st_mode & stat.S_IXUSR) != (mode == b"100755")):
                raise ValueError(f"来源 tracked 文件类型或执行位与 HEAD 不符：{file}")
            digest = hashlib.new(object_format, b"blob " + str(actual.st_size).encode() + b"\0")
            descriptor = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                        actual.st_dev, actual.st_ino, actual.st_mode, actual.st_size):
                    raise ValueError(f"来源 tracked 文件在检查期间改变：{file}")
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
                if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                        opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                    raise ValueError(f"来源 tracked 文件在检查期间改变：{file}")
            current = file.lstat()
            if (current.st_dev, current.st_ino, current.st_mode) != (
                    actual.st_dev, actual.st_ino, actual.st_mode):
                raise ValueError(f"来源 tracked 文件在检查期间被替换：{file}")
        if digest.hexdigest() != object_id.decode("ascii"):
            raise ValueError(f"来源存在其他修改（未提交）：tracked 原始字节与 HEAD blob 不符：{file}")


def verify_complete_repository(path: Path, source_root: Path | None = None,
                               gitlink_overrides: dict | None = None,
                               revision: str | None = None) -> None:
    git_environment()
    metadata = path / ".git"
    if metadata.is_symlink() or (metadata.is_dir() and any(
            item.is_symlink() for item in metadata.rglob("*"))):
        raise ValueError(f"来源 Git 元数据及对象库不能包含符号链接：{path}")
    def git_path(*arguments: str) -> Path:
        value = Path(git(path, *arguments))
        return value if value.is_absolute() else path / value

    git_metadata = path / ".git"
    git_directory_path = git_path("rev-parse", "--git-dir")
    if git_metadata.is_symlink() or git_directory_path.is_symlink():
        raise ValueError(f"SDK Git 元数据不能以符号链接借用其他来源：{path}")
    git_directory = git_directory_path.resolve(strict=True)
    if any(item.is_symlink() for item in git_directory.rglob("*")):
        raise ValueError(f"来源 Git 元数据及对象库不能包含符号链接：{path}")
    common_directory = git_path("rev-parse", "--git-common-dir").resolve(strict=True)
    if git_directory != common_directory:
        raise ValueError(f"SDK 来源不能使用借用主仓对象库的 linked worktree：{path}")
    source_root = (source_root or path).resolve(strict=True)
    if not path.resolve().is_relative_to(source_root):
        raise ValueError(f"SDK 子来源必须位于完整根来源目录：{path}")
    if path.resolve() == source_root:
        if not git_directory.is_relative_to(source_root):
            raise ValueError(f"SDK 根 Git 元数据必须位于来源自身目录：{path}")
    elif git_metadata.is_file():
        root_git_directory = Path(git(source_root, "rev-parse", "--absolute-git-dir")).resolve(strict=True)
        if not git_directory.is_relative_to(root_git_directory / "modules"):
            raise ValueError(f"SDK absorbed 子模块 Git 元数据必须归属根来源的 modules：{path}")
    elif git_directory != (path / ".git").resolve(strict=True):
        raise ValueError(f"SDK 子来源必须拥有自身 .git 目录：{path}")
    if git(path, "for-each-ref", "--format=%(refname)", "refs/replace/"):
        raise ValueError(f"SDK 来源不能包含 replace 对象引用：{path}")
    grafts = git_path("rev-parse", "--git-path", "info/grafts")
    if grafts.exists() or grafts.is_symlink():
        raise ValueError(f"SDK 来源不能包含 grafts 历史替换：{path}")
    if git_metadata.is_file():
        binding = subprocess.run(
            ["git", "-C", str(path), "config", "--local", "--path", "--get", "core.worktree"],
            text=True, capture_output=True, env=git_environment())
        if binding.returncode or not binding.stdout.strip():
            raise ValueError(f"SDK Git 元数据文件必须原生绑定当前来源：{path}")
        worktree = Path(binding.stdout.rstrip("\n"))
        if not worktree.is_absolute():
            worktree = git_directory / worktree
        if worktree.resolve() != path.resolve():
            raise ValueError(f"SDK Git 元数据文件指向另一工作树：{path}")
    objects = git_path("rev-parse", "--git-path", "objects")
    if (objects.is_symlink() or not objects.is_dir()
            or objects.resolve() != git_directory / "objects"
            or any(item.is_symlink() for item in objects.rglob("*"))):
        raise ValueError(f"SDK 来源对象库必须归属于该独立仓库，不能以符号链接借用对象：{path}")
    alternate = Path(git(path, "rev-parse", "--git-path", "objects/info/alternates"))
    if not alternate.is_absolute():
        alternate = path / alternate
    if alternate.exists() or alternate.is_symlink():
        raise ValueError(f"SDK 来源不能通过 alternates 借用其他仓库对象：{path}")
    if git(path, "rev-parse", "--show-toplevel") != str(path.resolve()):
        raise ValueError(f"SDK 来源未独立初始化：{path}")
    if git(path, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError(f"SDK 来源必须保有完整历史，不能使用 shallow clone：{path}")
    for line in git(path, "config", "--list").splitlines():
        key, _, value = line.partition("=")
        if key == "extensions.partialclone" or (
                key.startswith("remote.") and key.endswith((".promisor", ".partialclonefilter"))):
            raise ValueError(f"SDK 来源不能使用 partial clone：{path}")
        if key in ("core.sparsecheckout", "core.sparsecheckoutcone") and value.lower() in (
                "true", "yes", "on", "1"):
            raise ValueError(f"SDK 来源不能使用 sparse checkout：{path}")
    revision = revision or git(path, "rev-parse", "HEAD")
    if git(path, "rev-parse", "HEAD") != revision:
        raise ValueError(f"来源未锁定完整提交 {revision}：{path}")
    result = subprocess.run(["git", "-C", str(path), "fsck", "--connectivity-only",
                             "--no-dangling"], text=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, env=git_environment())
    if result.returncode:
        raise ValueError(f"SDK 来源对象不完整：{path}\n{result.stderr.strip()}")

    verify_object_bytes(path)
    if git(path, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError(f"来源存在其他修改（未提交的普通 untracked 内容）：{path}")
    verify_tracked_tree(path, source_root, gitlink_overrides or {}, revision)



def verify(sdk: Path, lock: dict) -> None:
    sdk = sdk.resolve(strict=True)
    lwip_path = lock["lwip"]["path"]
    if git(sdk, "rev-parse", "HEAD") != lock["idf"]["revision"]:
        raise ValueError("ESP-IDF 提交与 sdk-lock.json 不符")
    lwip = sdk / lwip_path
    if git(lwip, "rev-parse", "--show-toplevel") != str(lwip.resolve()):
        raise ValueError("lwIP 子模块未独立初始化")
    if git(lwip, "rev-parse", "HEAD") != lock["lwip"]["revision"]:
        raise ValueError("lwIP 尚未使用锁定的零窗口修正提交；请准备独立 SDK")
    verify_complete_repository(sdk, gitlink_overrides={lwip_path: lock["lwip"]["revision"]},
                               revision=lock["idf"]["revision"])


def prepare(output: Path, lock: dict) -> None:
    output = output.expanduser().absolute()
    if output.exists():
        raise ValueError("输出路径已存在；prepare 只创建新 SDK，已有 SDK 使用 check")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()  # Reserve ownership; no overwrite or implicit repair.
    git(output, "init", "-q")
    git(output, "remote", "add", "origin", lock["idf"]["repository"])
    git(output, "fetch", "origin", lock["idf"]["revision"])
    git(output, "checkout", "--detach", "FETCH_HEAD")
    git(output, "submodule", "update", "--init", "--recursive", "--checkout",
        "--no-recommend-shallow", "--jobs=8")
    lwip = output / lock["lwip"]["path"]
    git(lwip, "remote", "set-url", "origin", lock["lwip"]["repository"])
    git(lwip, "fetch", "origin", lock["lwip"]["revision"])
    git(lwip, "checkout", "--detach", "FETCH_HEAD")
    verify(output, lock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("--path", required=True, type=Path, help="新 SDK 输出路径或待检查 SDK")
    parser.add_argument("--quiet", action="store_true", help="成功时不输出，用于构建守卫")
    args = parser.parse_args()
    try:
        lock = read_lock()
        if args.action == "prepare":
            if not args.quiet:
                print(f"ESP FRP SDK\n  操作  准备独立 checkout\n  路径  {args.path}\n", flush=True)
            prepare(args.path, lock)
        else:
            verify(args.path, lock)
        if not args.quiet:
            print(f"ESP FRP SDK\n  结果  已验证\n  IDF   {lock['idf']['revision']}\n"
                  f"  lwIP  {lock['lwip']['revision']}\n  路径  {args.path.resolve()}")
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"ESP FRP SDK\n  结果  失败\n  原因  {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

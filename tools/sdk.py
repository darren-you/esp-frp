#!/usr/bin/env python3
"""只准备或校验组件锁定的单一正式 SDK 派生；check 不下载或执行 SDK 脚本。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

LOCK_PATH = Path(__file__).resolve().parents[1] / "sdk-lock.json"
DERIVATION_STAMP = "esp-sdk-derivation.json"
RECIPE_REPOSITORY = "https://github.com/darren-you/esp-base.git"


def git_environment() -> dict:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE"):
        if os.environ.get(name):
            raise ValueError(f"Git 环境不能重定向来源或 alternate 对象：{name}")
    # Every Git command reads the actual locked objects, regardless of caller flags.
    return {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}


def git_command(path: Path, *args: str) -> list[str]:
    # 原始对象/索引读取及新仓 fetch 不执行外部监控或 hooks；其余配置仍按实际作用域读取。
    return ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(path), *args]


def apply_git_command(path: Path, *args: str) -> list[str]:
    # 精确容量原文与 patch 使用 LF，apply 不继承宿主／平台的默认 CRLF。
    return git_command(path, "-c", "core.autocrlf=false", "-c", "core.eol=lf", *args)


def reject_builtin_content_conversions(path: Path, files: list[str], patch: bytes) -> None:
    """在首写前读取实际 worktree/info/global 属性，拒绝会改写受管字节的转换。"""
    result = subprocess.run(
        git_command(path, "check-attr", "-z", "text", "eol", "working-tree-encoding", "ident", "--", *files),
        check=True, capture_output=True, env=git_environment())
    fields = result.stdout.split(b"\0")
    if fields[-1] != b"" or (len(fields) - 1) % 3:
        raise ValueError("SDK 内置 Git 属性输出不完整")
    attributes = {relative: {} for relative in files}
    for offset in range(0, len(fields) - 1, 3):
        relative, name, value = (part.decode() for part in fields[offset:offset + 3])
        if relative not in attributes:
            raise ValueError("SDK 内置 Git 属性越出受管路径")
        attributes[relative][name] = value
    patch_outputs = {relative: b"" for relative in files}
    current = None
    for line in patch.splitlines():
        if line.startswith(b"diff --git "):
            current = next((relative for relative in files
                            if line == b"diff --git a/" + relative.encode() + b" b/" + relative.encode()), None)
        elif current is not None and line.startswith((b"+", b" ")) and not line.startswith(b"+++"):
            patch_outputs[current] += line[1:] + b"\n"
    for relative, values in attributes.items():
        if set(values) != {"text", "eol", "working-tree-encoding", "ident"}:
            raise ValueError("SDK 内置 Git 属性集合不完整")
        encoding = values["working-tree-encoding"]
        if ((values["text"] != "unset" and values["eol"] == "crlf")
                or encoding not in ("", "unspecified", "unset") and encoding.upper().replace("-", "") != "UTF8"
                or values["ident"] == "set" and re.search(rb"\$Id(?:\$|:[^\r\n]*\$)",
                                                         (path / relative).read_bytes() + patch_outputs[relative])):
            raise ValueError(f"SDK 内置 Git 转换会改变受管原始字节：{relative}：{path}")


def reject_external_content_filters(path: Path, files: list[str]) -> None:
    """首写前只拒绝实际补丁路径选中的可执行驱动，未使用的注册不影响装配。"""
    result = subprocess.run(
        git_command(path, "check-attr", "-z", "--stdin", "filter"),
        input=b"".join(relative.encode() + b"\0" for relative in files),
        check=True, capture_output=True, env=git_environment())
    fields = result.stdout.split(b"\0")
    if fields[-1] != b"" or len(fields) - 1 != len(files) * 3:
        raise ValueError("SDK 外部 Git filter 属性输出不完整")
    attributes = {}
    for offset in range(0, len(fields) - 1, 3):
        relative, attribute, driver = (part.decode() for part in fields[offset:offset + 3])
        if relative not in files or relative in attributes or attribute != "filter":
            raise ValueError("SDK 外部 Git filter 属性越出受管路径")
        attributes[relative] = driver
    keys = set(git(path, "config", "--null", "--name-only", "--list").split("\0"))
    for relative, driver in attributes.items():
        # check-attr 的 set/unset/unspecified 也可能是同名驱动的字面值；
        # 不以这些输出文本跳过实际配置中的可执行驱动。
        executable = any("filter." + driver + "." + kind in keys and
                         git(path, "config", "--get", "filter." + driver + "." + kind)
                         for kind in ("clean", "smudge", "process"))
        if not executable:
            continue
        if driver in ("set", "unset", "unspecified"):
            # 原生属性输出混用布尔/未设置与同名字面值。仅这三个固定 ASCII
            # 名称用空输入、禁用驱动且 required 的无写入 hash 判断真实绑定。
            probe = subprocess.run(git_command(
                path, "-c", "filter." + driver + ".clean=",
                "-c", "filter." + driver + ".process=",
                "-c", "filter." + driver + ".required=true",
                "hash-object", "--path=" + relative, "--stdin"),
                input=b"", capture_output=True, env=git_environment())
            if (probe.returncode == 0 and
                    probe.stdout.strip() == b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"):
                continue
        raise ValueError(f"SDK 装配不能执行外部 Git filter：{driver}：{relative}：{path}")


def verify_repository_origin(path: Path, expected: str) -> None:
    """配方身份同时绑定原始唯一 origin 与实际 fetch URL，不接受来源重写。"""
    pattern = r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?"
    expected_match = re.fullmatch(pattern, expected)
    if not expected_match:
        raise ValueError("SDK 配方 origin 身份无效")
    raw = git(path, "config", "--local", "--get-all", "remote.origin.url").splitlines()
    fetch = git(path, "remote", "get-url", "--all", "origin").splitlines()
    if len(raw) != 1 or len(fetch) != 1:
        raise ValueError(f"SDK origin 必须解析为唯一 fetch 来源：{path}")
    for value in raw + fetch:
        match = re.fullmatch(pattern, value)
        if not match or match[1].casefold() != expected_match[1].casefold():
            raise ValueError(f"SDK origin fetch 身份与配方不符：{path}")


def git(path: Path, *args: str) -> str:
    return subprocess.run(
        git_command(path, *args), check=True, capture_output=True, text=True, env=git_environment()
    ).stdout.rstrip("\n")


def prepare_git(path: Path, *args: str) -> str:
    """隔离新 SDK 的写入与 recipe init；来源查询仍消费宿主实际配置。"""
    environment = git_environment()
    for name in ("GIT_CONFIG", "GIT_CONFIG_PARAMETERS"):
        environment.pop(name, None)
    environment.update(GIT_CONFIG_SYSTEM="/dev/null", GIT_CONFIG_GLOBAL="/dev/null",
                       GIT_CONFIG_COUNT="0", GIT_TEMPLATE_DIR="")
    return subprocess.run(
        git_command(path, "-c", "init.templateDir=", *args),
        check=True, capture_output=True, text=True, env=environment
    ).stdout.rstrip("\n")


def git_boolean(path: Path, key: str) -> bool:
    """按 Git 的作用域、include 与原生布尔规则读取最终有效值。"""
    result = subprocess.run(
        git_command(path, "config", "--bool", "--get", key),
        text=True, capture_output=True, env=git_environment())
    if result.returncode == 1:
        return False
    value = result.stdout.strip()
    if result.returncode == 0 and value in ("true", "false"):
        return value == "true"
    raise ValueError(f"来源 Git 布尔配置无效：{key}：{path}\n{result.stderr.strip()}")


def verify_object_bytes(path: Path) -> None:
    """重算独立对象库每个对象的原始 Git OID，不改写或忽略历史内容。"""
    object_format = git(path, "rev-parse", "--show-object-format")
    if object_format not in ("sha1", "sha256"):
        raise ValueError("来源 Git 对象摘要格式不受支持")
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(git_command(path, "cat-file", "--batch-all-objects",
                                    "--batch", "--unordered"), stdout=subprocess.PIPE,
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


def verify_tracked_tree(path: Path, source_root: Path, gitlink_overrides: dict, revision: str,
                        capacity_files: dict | None = None, capacity_seen: set | None = None,
                        capacity_patched: bool = False, capacity_stamp: str | None = None) -> None:
    """直接以 HEAD 的 Git blob 字节与类型核对源码，不读取 index 的内容提示。"""
    result = subprocess.run(git_command(path, "ls-tree", "-r", "-z", revision),
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
    index = subprocess.run(git_command(path, "ls-files", "--stage", "-z"),
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
                                       gitlink_overrides=gitlink_overrides, revision=expected,
                                       capacity_files=capacity_files, capacity_seen=capacity_seen,
                                       capacity_patched=capacity_patched, capacity_stamp=capacity_stamp)
            continue
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise ValueError(f"来源 HEAD 包含不支持的文件类型：{file}")
        capacity_item = (capacity_files or {}).get(file.relative_to(source_root).as_posix())
        if capacity_item and (mode != b"100644" or path.resolve() != (
                source_root if capacity_item["repository"] == "idf" else source_root / "components/heap/tlsf")):
            raise ValueError(f"SDK 容量原件必须属于正确仓库的普通非执行 blob：{file}")
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
            capacity_digest = hashlib.sha256() if capacity_item else None
            descriptor = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                        actual.st_dev, actual.st_ino, actual.st_mode, actual.st_size):
                    raise ValueError(f"来源 tracked 文件在检查期间改变：{file}")
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    if capacity_digest is not None:
                        capacity_digest.update(chunk)
                after = os.fstat(stream.fileno())
                if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                        opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                    raise ValueError(f"来源 tracked 文件在检查期间改变：{file}")
            current = file.lstat()
            if (current.st_dev, current.st_ino, current.st_mode) != (
                    actual.st_dev, actual.st_ino, actual.st_mode):
                raise ValueError(f"来源 tracked 文件在检查期间被替换：{file}")
        if capacity_item:
            original = subprocess.run(git_command(path, "cat-file", "blob", object_id.decode("ascii")),
                                      check=True, capture_output=True, env=git_environment()).stdout
            if hashlib.sha256(original).hexdigest() != capacity_item["before_sha256"]:
                raise ValueError(f"SDK 容量原件 HEAD blob 与 before 摘要不符：{file}")
            expected = capacity_item["after_sha256"] if capacity_patched else capacity_item["before_sha256"]
            if capacity_digest.hexdigest() != expected:
                raise ValueError(f"SDK 容量原始字节与精确派生摘要不符：{file}")
            capacity_seen.add(file.relative_to(source_root).as_posix())
        if (not capacity_item or not capacity_patched) and digest.hexdigest() != object_id.decode("ascii"):
            raise ValueError(f"来源存在其他修改（未提交）：tracked 原始字节与 HEAD blob 不符：{file}")


def verify_complete_repository(path: Path, source_root: Path | None = None,
                               gitlink_overrides: dict | None = None,
                               revision: str | None = None,
                               capacity_files: dict | None = None, capacity_seen: set | None = None,
                               capacity_patched: bool = False, capacity_stamp: str | None = None) -> None:
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
            git_command(path, "config", "--local", "--path", "--get", "core.worktree"),
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
    config_keys = set(git(path, "config", "--null", "--name-only", "--list").split("\0"))
    for key in sorted(config_keys):
        if key == "extensions.partialclone" or (
                key.startswith("remote.") and key.endswith(".partialclonefilter")):
            raise ValueError(f"SDK 来源不能使用 partial clone：{path}")
        if key.startswith("remote.") and key.endswith(".promisor") and git_boolean(path, key):
            raise ValueError(f"SDK 来源不能使用 partial clone：{path}")
    # Git resolves include, scope precedence and every accepted boolean spelling.
    # Cone only selects a mode; it does not enable sparse checkout on its own.
    if git_boolean(path, "core.sparseCheckout"):
        raise ValueError(f"SDK 来源不能使用 sparse checkout：{path}")
    revision = revision or git(path, "rev-parse", "HEAD")
    if git(path, "rev-parse", "HEAD") != revision:
        raise ValueError(f"来源未锁定完整提交 {revision}：{path}")
    result = subprocess.run(git_command(path, "fsck", "--connectivity-only",
                             "--no-dangling"), text=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, env=git_environment())
    if result.returncode:
        raise ValueError(f"SDK 来源对象不完整：{path}\n{result.stderr.strip()}")

    verify_object_bytes(path)
    verify_tracked_tree(path, source_root, gitlink_overrides or {}, revision,
                        capacity_files, capacity_seen, capacity_patched, capacity_stamp)
    others = {name for name in git(path, "ls-files", "--others", "-z").split("\0") if name}
    if capacity_patched and capacity_stamp and path.resolve() == source_root:
        others.discard(capacity_stamp)
    if others:
        raise ValueError(f"来源存在其他修改（含 ignored 的未提交 untracked 内容）：{path}")


def git_bytes(path: Path, object_path: str) -> bytes:
    return subprocess.run(git_command(path, "show", object_path),
                          check=True, capture_output=True, env=git_environment()).stdout


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON 存在重复字段：{key}")
        result[key] = value
    return result


def decode_json(data: bytes) -> dict:
    value = json.loads(data, object_pairs_hook=object_fields)
    if not isinstance(value, dict):
        raise ValueError("SDK 声明必须是 JSON object")
    return value


def fields(value: object, expected: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} 字段与正式合同不符")


def sha(value: object, size: int, name: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{size}}}", value):
        raise ValueError(f"{name} 必须锁定完整摘要或提交")


def source_path(value: object, name: str) -> str:
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
            or value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/"))
            or str(PurePosixPath(value)) != value):
        raise ValueError(f"{name} 必须是规范仓内相对路径")
    return value


def repository(entry: object, keys: set[str], name: str) -> None:
    fields(entry, keys, name)
    sha(entry["revision"], 40, name)
    if not isinstance(entry["repository"], str) or not re.fullmatch(
            r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9-]+\.git", entry["repository"]):
        raise ValueError(f"{name} 必须使用明确的公开 GitHub HTTPS 源")


def read_lock() -> dict:
    lock = decode_json(LOCK_PATH.read_bytes())
    fields(lock, {"schema_version", "idf", "lwip", "sdk_derivation"}, "组件 SDK 锁")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 2:
        raise ValueError("组件必须锁定正式 SDK 派生，不接受旧 SDK 锁")
    repository(lock["idf"], {"repository", "revision"}, "idf")
    repository(lock["lwip"], {"repository", "revision", "path"}, "lwip")
    if lock["lwip"]["path"] != "components/lwip/lwip":
        raise ValueError("lwIP 装配位置与 ESP-IDF 合同不符")
    entry = lock["sdk_derivation"]
    repository(entry, {"repository", "revision", "path", "sha256"}, "sdk_derivation")
    if entry["repository"] != RECIPE_REPOSITORY or entry["path"] != "sdk-lock.json":
        raise ValueError("SDK 派生必须来自精确保存的 ESP Base 唯一 recipe")
    sha(entry["sha256"], 64, "sdk_derivation.sha256")
    return lock


def recipe_from_bytes(data: bytes, lock: dict) -> dict:
    if digest(data) != lock["sdk_derivation"]["sha256"]:
        raise ValueError("SDK 派生清单摘要与组件锁不符")
    recipe = decode_json(data)
    fields(recipe, {"schema_version", "idf", "lwip", "tlsf", "managed_patches", "derivation_stamp"},
           "SDK 派生 recipe")
    if type(recipe["schema_version"]) is not int or recipe["schema_version"] != 2:
        raise ValueError("SDK 派生 recipe 版本不符")
    if recipe["idf"] != lock["idf"] or recipe["lwip"] != lock["lwip"]:
        raise ValueError("SDK 派生官方基线与组件锁不符")
    fields(recipe["tlsf"], {"path", "revision"}, "tlsf")
    sha(recipe["tlsf"]["revision"], 40, "tlsf.revision")
    if recipe["tlsf"]["path"] != "components/heap/tlsf" or recipe["derivation_stamp"] != DERIVATION_STAMP:
        raise ValueError("TLSF 或 SDK 派生清单装配路径不符")
    patches = recipe["managed_patches"]
    if not isinstance(patches, list) or len(patches) != 2:
        raise ValueError("SDK 派生必须精确声明 IDF 与 TLSF 两份修改")
    repositories = set()
    resources = set()
    for patch in patches:
        fields(patch, {"repository", "path", "sha256", "files"}, "managed_patch")
        name = patch["repository"]
        if name not in ("idf", "tlsf") or name in repositories:
            raise ValueError("SDK 派生修改仓库重复或未知")
        repositories.add(name)
        path = source_path(patch["path"], "managed_patch.path")
        if path in resources:
            raise ValueError("SDK 派生 patch 来源重复")
        resources.add(path)
        sha(patch["sha256"], 64, "managed_patch.sha256")
        declarations = patch["files"]
        if not isinstance(declarations, list) or not declarations:
            raise ValueError("SDK 派生修改文件不得为空")
        paths = set()
        for item in declarations:
            fields(item, {"path", "before_sha256", "after_sha256"}, "managed_file")
            path = source_path(item["path"], "managed_file.path")
            if path in paths:
                raise ValueError("SDK 派生修改文件重复")
            paths.add(path)
            sha(item["before_sha256"], 64, "managed_file.before_sha256")
            sha(item["after_sha256"], 64, "managed_file.after_sha256")
    return recipe


def read_source_file(path: Path, *, mode: int | None = None) -> tuple[bytes, tuple]:
    """稳定读取小型配方输入，不跟随链接，不在 FIFO 的 open 上等待。"""
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"容量配方输入缺失：{path}") from error
    if not stat.S_ISREG(before.st_mode) or (mode is not None and stat.S_IMODE(before.st_mode) != mode):
        raise ValueError(f"容量配方输入必须为既定权限的普通文件：{path}")
    if before.st_size > 65536:
        raise ValueError(f"容量配方输入大小越界：{path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        if identity(opened) != identity(before):
            raise ValueError(f"容量配方输入在打开时改变：{path}")
        content = stream.read(65537)
        after = os.fstat(stream.fileno())
        current = path.lstat()
        if len(content) != before.st_size or identity(after) != identity(before) or identity(current) != identity(before):
            raise ValueError(f"容量配方输入在读取时改变：{path}")
    return content, identity(before)


def regular_file(root: Path, relative: str) -> Path:
    source_path(relative, "SDK 文件路径")
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError(f"SDK 输入不得是符号链接：{relative}")
    if not path.is_file():
        raise ValueError(f"SDK 输入必须是普通文件：{relative}")
    return path


def verify_tree(sdk: Path, lock: dict, recipe: dict, *, patched: bool) -> None:
    sdk = sdk.resolve(strict=True)
    if (git(sdk, "rev-parse", "--show-toplevel") != str(sdk)
            or git(sdk, "rev-parse", "HEAD") != lock["idf"]["revision"]):
        raise ValueError("ESP-IDF 独立 Git 根或提交与组件锁不符")
    lwip_path = lock["lwip"]["path"]
    lwip = sdk / lwip_path
    verify_repository_origin(sdk, lock["idf"]["repository"])
    verify_repository_origin(lwip, lock["lwip"]["repository"])
    if (git(lwip, "rev-parse", "--show-toplevel") != str(lwip.resolve())
            or git(lwip, "rev-parse", "HEAD") != lock["lwip"]["revision"]):
        raise ValueError("lwIP 尚未使用锁定的零窗口修正提交或未独立初始化")
    tlsf_path = recipe["tlsf"]["path"]
    tlsf = sdk / tlsf_path
    if (git(tlsf, "rev-parse", "--show-toplevel") != str(tlsf.resolve())
            or git(tlsf, "rev-parse", "HEAD") != recipe["tlsf"]["revision"]):
        raise ValueError("TLSF 独立 Git 根或官方提交与派生清单不符")
    tlsf_entry = git(sdk, "ls-tree", lock["idf"]["revision"], "--", tlsf_path)
    if tlsf_entry != "160000 commit " + recipe["tlsf"]["revision"] + "\t" + tlsf_path:
        raise ValueError("TLSF 必须保持锁定 IDF 的原生 gitlink 身份")
    capacity_files = {}
    for declaration in recipe["managed_patches"]:
        name = declaration["repository"]
        for item in declaration["files"]:
            relative = item["path"] if name == "idf" else tlsf_path + "/" + item["path"]
            if relative in capacity_files:
                raise ValueError("SDK 正式派生原件路径重复或越入另一来源")
            capacity_files[relative] = {**item, "repository": name}
    seen = set()
    verify_complete_repository(sdk, source_root=sdk,
                               gitlink_overrides={lwip_path: lock["lwip"]["revision"]},
                               revision=lock["idf"]["revision"], capacity_files=capacity_files,
                               capacity_seen=seen, capacity_patched=patched,
                               capacity_stamp=DERIVATION_STAMP)
    if seen != set(capacity_files):
        raise ValueError("SDK 正式派生原件不在锁定递归 HEAD 树中")

    # 上述递归原始树已逐字核对索引、派生集合、ignored 内容和 gitlink。
    # 不再运行会执行外部 clean/filter 或 Shell 子模块入口的 status/diff。



def verify(sdk: Path, lock: dict) -> None:
    sdk = sdk.resolve(strict=True)
    stamp = regular_file(sdk, DERIVATION_STAMP)
    data, identity = read_source_file(stamp, mode=0o400)
    recipe = recipe_from_bytes(data, lock)
    verify_tree(sdk, lock, recipe, patched=True)
    if read_source_file(stamp, mode=0o400) != (data, identity):
        raise ValueError("SDK 派生清单在来源检查期间改变")


def fetch_recipe(destination: Path, lock: dict) -> tuple[bytes, dict, list[tuple[dict, Path]]]:
    entry = lock["sdk_derivation"]
    destination.mkdir()
    prepare_git(destination, "init", "-q", "-b", "master")
    git(destination, "remote", "add", "origin", entry["repository"])
    git(destination, "fetch", "--no-filter", "origin", entry["revision"])
    if git(destination, "rev-parse", "FETCH_HEAD") != entry["revision"]:
        raise ValueError("SDK recipe 来源提交不符")
    data = git_bytes(destination, entry["revision"] + ":" + entry["path"])
    recipe = recipe_from_bytes(data, lock)
    resources = []
    for declaration in recipe["managed_patches"]:
        content = git_bytes(destination, entry["revision"] + ":" + declaration["path"])
        if digest(content) != declaration["sha256"]:
            raise ValueError(f"SDK recipe patch 摘要不符：{declaration['path']}")
        path = destination / declaration["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        resources.append((declaration, path))
    return data, recipe, resources


def apply_recipe(sdk: Path, lock: dict, data: bytes, recipe: dict,
                 resources: list[tuple[dict, Path]]) -> None:
    if recipe_from_bytes(data, lock) != recipe:
        raise ValueError("SDK recipe 输入与已锁定清单不符")
    if [declaration for declaration, _ in resources] != recipe["managed_patches"]:
        raise ValueError("SDK patch 输入集合与唯一 recipe 不符")
    verify_tree(sdk, lock, recipe, patched=False)
    repositories = {"idf": sdk, "tlsf": sdk / recipe["tlsf"]["path"]}
    for declaration in recipe["managed_patches"]:
        reject_external_content_filters(repositories[declaration["repository"]],
                                        [item["path"] for item in declaration["files"]])
    for declaration, path in resources:
        if digest(path.read_bytes()) != declaration["sha256"]:
            raise ValueError("SDK patch 输入摘要不符")
        repo = repositories[declaration["repository"]]
        names = []
        for line in git(repo, "apply", "--numstat", str(path)).splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                raise ValueError("SDK patch 文件集合不可解析")
            names.append(parts[2])
        if len(names) != len(set(names)) or set(names) != {item["path"] for item in declaration["files"]}:
            raise ValueError("SDK patch 修改文件集合与唯一 recipe 不符")
        reject_builtin_content_conversions(repo, names, path.read_bytes())
        subprocess.run(apply_git_command(repo, "apply", "--check", "--whitespace=nowarn", str(path)),
                       check=True, capture_output=True, env=git_environment())
    for declaration, path in resources:
        subprocess.run(apply_git_command(repositories[declaration["repository"]], "apply", "--whitespace=nowarn", str(path)),
                       check=True, capture_output=True, env=git_environment())
    descriptor = os.open(sdk / DERIVATION_STAMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    verify(sdk, lock)


def prepare(output: Path, lock: dict) -> None:
    output = output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("输出路径已存在；prepare 只创建新 SDK，已有 SDK 使用 check")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    with tempfile.TemporaryDirectory(prefix="esp-sdk-recipe-") as temporary:
        data, recipe, resources = fetch_recipe(Path(temporary) / "recipe", lock)
        prepare_git(output, "init", "-q", "-b", "master")
        git(output, "remote", "add", "origin", lock["idf"]["repository"])
        # 新根和递归 checkout 使用隔离配置，实际补丁路径在 apply 首写前统一核验。
        git(output, "fetch", "--no-filter", "origin", lock["idf"]["revision"])
        prepare_git(output, "checkout", "--detach", "FETCH_HEAD")
        prepare_git(output, "submodule", "update", "--init", "--recursive", "--checkout", "--no-recommend-shallow", "--jobs=8")
        lwip = output / lock["lwip"]["path"]
        git(lwip, "remote", "set-url", "origin", lock["lwip"]["repository"])
        git(lwip, "fetch", "--no-filter", "origin", lock["lwip"]["revision"])
        prepare_git(lwip, "checkout", "--detach", "FETCH_HEAD")
        apply_recipe(output, lock, data, recipe, resources)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--quiet", action="store_true", help="构建守卫成功时不输出")
    args = parser.parse_args()
    try:
        lock = read_lock()
        if args.action == "prepare":
            if not args.quiet:
                print(f"ESP SDK\n  操作  准备正式派生\n  路径  {args.path}\n", flush=True)
            prepare(args.path, lock)
        else:
            verify(args.path, lock)
        if not args.quiet:
            print(f"ESP SDK\n  结果  已验证正式派生\n  IDF   {lock['idf']['revision']}\n"
                  f"  lwIP  {lock['lwip']['revision']}\n  清单  {lock['sdk_derivation']['sha256']}\n"
                  f"  路径  {args.path.resolve()}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ESP SDK\n  结果  失败\n  原因  {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

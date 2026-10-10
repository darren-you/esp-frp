#!/usr/bin/env python3
"""只准备或校验组件锁定的单一正式 SDK 派生；check 不下载或执行 SDK 脚本。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

LOCK_PATH = Path(__file__).resolve().parents[1] / "sdk-lock.json"
DERIVATION_STAMP = "esp-sdk-derivation.json"
RECIPE_REPOSITORY = "https://github.com/darren-you/esp-base.git"


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"Git 失败：{' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.rstrip("\n")


def git_bytes(path: Path, object_path: str) -> bytes:
    return subprocess.run(["git", "-C", str(path), "show", object_path],
                          check=True, capture_output=True).stdout


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
    if (git(lwip, "rev-parse", "--show-toplevel") != str(lwip.resolve())
            or git(lwip, "rev-parse", "HEAD") != lock["lwip"]["revision"]):
        raise ValueError("lwIP 尚未使用锁定的零窗口修正提交或未独立初始化")
    if git(lwip, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none"):
        raise ValueError("lwIP checkout 存在未提交内容")
    tlsf_path = recipe["tlsf"]["path"]
    tlsf = sdk / tlsf_path
    if (git(tlsf, "rev-parse", "--show-toplevel") != str(tlsf.resolve())
            or git(tlsf, "rev-parse", "HEAD") != recipe["tlsf"]["revision"]):
        raise ValueError("TLSF 独立 Git 根或官方提交与派生清单不符")
    repositories = {"idf": sdk, "tlsf": tlsf}
    for patch in recipe["managed_patches"]:
        name = patch["repository"]
        repo = repositories[name]
        if git(repo, "diff", "--cached", "--name-only"):
            raise ValueError(f"SDK 索引存在未提交内容：{name}")
        expected = {" M " + item["path"] for item in patch["files"]} if patched else set()
        if name == "idf":
            expected.add(" M " + lwip_path)
            if patched:
                expected.update({" M " + tlsf_path, "?? " + DERIVATION_STAMP})
        actual = git(repo, "status", "--porcelain", "--untracked-files=normal",
                     "--ignore-submodules=none").splitlines()
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise ValueError(f"SDK 存在正式派生声明之外的其他修改或缺失：{name}")
        for item in patch["files"]:
            original = git_bytes(repo, "HEAD:" + item["path"])
            if digest(original) != item["before_sha256"]:
                raise ValueError(f"SDK 官方原文摘要不符：{name}/{item['path']}")
            current = regular_file(repo, item["path"]).read_bytes()
            wanted = item["after_sha256"] if patched else item["before_sha256"]
            if digest(current) != wanted:
                raise ValueError(f"SDK 正式派生源码摘要不符：{name}/{item['path']}")
    for line in git(sdk, "submodule", "status", "--recursive").splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            raise ValueError("SDK 子模块状态不可解析")
        revision, path = parts[:2]
        if revision.startswith(("-", "U")):
            raise ValueError(f"SDK 子模块未就绪：{path}")
        if revision.startswith("+") and (path != lwip_path or revision[1:] != lock["lwip"]["revision"]):
            raise ValueError(f"SDK 子模块版本漂移：{path}")


def verify(sdk: Path, lock: dict) -> None:
    sdk = sdk.resolve(strict=True)
    data = regular_file(sdk, DERIVATION_STAMP).read_bytes()
    recipe = recipe_from_bytes(data, lock)
    verify_tree(sdk, lock, recipe, patched=True)


def fetch_recipe(destination: Path, lock: dict) -> tuple[bytes, dict, list[tuple[dict, Path]]]:
    entry = lock["sdk_derivation"]
    destination.mkdir()
    git(destination, "init", "-q", "-b", "master")
    git(destination, "remote", "add", "origin", entry["repository"])
    git(destination, "fetch", "--depth=1", "origin", entry["revision"])
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
        git(repo, "apply", "--check", "--whitespace=nowarn", str(path))
    for declaration, path in resources:
        git(repositories[declaration["repository"]], "apply", "--whitespace=nowarn", str(path))
    descriptor = os.open(sdk / DERIVATION_STAMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        git(output, "init", "-q", "-b", "master")
        git(output, "remote", "add", "origin", lock["idf"]["repository"])
        git(output, "fetch", "--depth=1", "origin", lock["idf"]["revision"])
        git(output, "checkout", "--detach", "FETCH_HEAD")
        git(output, "submodule", "update", "--init", "--recursive", "--depth=1", "--jobs=8")
        lwip = output / lock["lwip"]["path"]
        git(lwip, "remote", "set-url", "origin", lock["lwip"]["repository"])
        git(lwip, "fetch", "--depth=1", "origin", lock["lwip"]["revision"])
        git(lwip, "checkout", "--detach", "FETCH_HEAD")
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

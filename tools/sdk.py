#!/usr/bin/env python3
"""准备或验证由公开精确提交构成的独立 SDK，不修改其他 SDK。"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

LOCK_PATH = Path(__file__).resolve().parents[1] / "sdk-lock.json"


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True)
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


def verify_complete_repository(path: Path) -> None:
    if os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES") or os.environ.get("GIT_OBJECT_DIRECTORY"):
        raise ValueError("SDK 来源不能使用环境提供的 alternate 对象目录")
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
    result = subprocess.run(["git", "-C", str(path), "fsck", "--connectivity-only",
                             "--no-dangling"], text=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError(f"SDK 来源对象不完整：{path}\n{result.stderr.strip()}")


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
    if git(lwip, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("lwIP checkout 存在未提交内容")
    if git(sdk, "diff", "--cached", "--name-only"):
        raise ValueError("SDK 索引存在未提交内容")
    changes = git(sdk, "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none")
    # The locked lwIP commit is the sole intentional deviation from IDF's gitlink.
    if changes != "M " + lwip_path:
        raise ValueError("SDK 必须仅包含锁定 lwIP gitlink 差异，不能有其他修改")
    verify_complete_repository(sdk)
    for line in git(sdk, "submodule", "status", "--recursive").splitlines():
        # git() strips the first leading space; normal lines may begin at SHA.
        normalized = line.strip()
        parts = normalized.split()
        if len(parts) < 2:
            raise ValueError("SDK 子模块状态不可解析")
        revision, path = parts[:2]
        if revision.startswith(("-", "U")):
            raise ValueError(f"SDK 子模块未就绪：{path}")
        if revision.startswith("+") and (path != lwip_path or revision[1:] != lock["lwip"]["revision"]):
            raise ValueError(f"SDK 子模块版本漂移：{path}")
        verify_complete_repository(sdk / path)


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

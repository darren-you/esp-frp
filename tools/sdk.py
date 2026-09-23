#!/usr/bin/env python3
"""准备或验证由公开精确提交构成的独立 SDK，不修改其他 SDK。"""
from __future__ import annotations

import argparse
import json
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


def prepare(output: Path, lock: dict) -> None:
    output = output.expanduser().absolute()
    if output.exists():
        raise ValueError("输出路径已存在；prepare 只创建新 SDK，已有 SDK 使用 check")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()  # Reserve ownership; no overwrite or implicit repair.
    git(output, "init", "-q")
    git(output, "remote", "add", "origin", lock["idf"]["repository"])
    git(output, "fetch", "--depth=1", "origin", lock["idf"]["revision"])
    git(output, "checkout", "--detach", "FETCH_HEAD")
    git(output, "submodule", "update", "--init", "--recursive", "--depth=1", "--jobs=8")
    lwip = output / lock["lwip"]["path"]
    git(lwip, "remote", "set-url", "origin", lock["lwip"]["repository"])
    git(lwip, "fetch", "--depth=1", "origin", lock["lwip"]["revision"])
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

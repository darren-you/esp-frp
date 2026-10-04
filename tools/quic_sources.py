#!/usr/bin/env python3
"""准备或核验 QUIC 原型的精确公开依赖，不修改已有 checkout。"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

LOCK_PATH = Path(__file__).resolve().parents[1] / "quic-lock.json"

def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True,
                            timeout=180)
    if result.returncode:
        raise RuntimeError(f"Git 失败：{' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.strip()

def verify(path: Path, entry: dict) -> None:
    if git(path, "rev-parse", "--show-toplevel") != str(path.resolve()):
        raise ValueError("依赖必须是独立 checkout")
    if git(path, "rev-parse", "HEAD") != entry["revision"]:
        raise ValueError(f"依赖未锁定完整提交 {entry['revision']}")
    if git(path, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("依赖 checkout 有未提交内容")

def prepare(path: Path, entry: dict) -> None:
    path.mkdir(parents=True, exist_ok=False)
    git(path, "init", "-q")
    git(path, "remote", "add", "origin", entry["repository"])
    git(path, "fetch", "--depth=1", "origin", entry["revision"])
    git(path, "checkout", "--detach", "FETCH_HEAD")
    verify(path, entry)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("--ngtcp2-path", required=True, type=Path)
    parser.add_argument("--picotls-path", required=True, type=Path)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK_PATH.read_text())
        if lock["schema_version"] != 1:
            raise ValueError("不支持的依赖锁")
        entries = ((args.ngtcp2_path, lock["ngtcp2"]), (args.picotls_path, lock["picotls"]))
        for path, entry in entries:
            if not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]) or not re.fullmatch(
                    r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9-]+\.git", entry["repository"]):
                raise ValueError("依赖必须是精确公开 Git 提交")
            if args.action == "prepare" and path.exists():
                raise ValueError("prepare 仅创建新目录；已有依赖使用 check")
        for path, entry in entries:
            path = path.expanduser().absolute()
            if args.action == "prepare":
                prepare(path, entry)
            else:
                verify(path, entry)
        if not args.quiet:
            print("ESP FRP QUIC 依赖\n  结果  精确源码已验证\n"
                  f"  ngtcp2 {lock['ngtcp2']['revision']}\n  Picotls {lock['picotls']['revision']}")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"ESP FRP QUIC 依赖\n  结果  失败\n  原因  {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())

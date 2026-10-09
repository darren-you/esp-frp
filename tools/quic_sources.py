#!/usr/bin/env python3
"""准备或核验 QUIC 原型的精确公开依赖，不修改已有 checkout。"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

LOCK_PATH = Path(__file__).resolve().parents[1] / "quic-lock.json"

def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"Git 失败：{' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.strip()

def verify(path: Path, entry: dict) -> None:
    if os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES") or os.environ.get("GIT_OBJECT_DIRECTORY"):
        raise ValueError("依赖不能使用环境提供的 alternate 对象目录")
    if git(path, "rev-parse", "--show-toplevel") != str(path.resolve()):
        raise ValueError("依赖必须是独立 checkout")
    if git(path, "rev-parse", "HEAD") != entry["revision"]:
        raise ValueError(f"依赖未锁定完整提交 {entry['revision']}")
    if git(path, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("依赖 checkout 有未提交内容")
    sources = [path]
    for line in git(path, "submodule", "status", "--recursive").splitlines():
        revision, relative = line.strip().split()[:2]
        if revision.startswith(("-", "+", "U")):
            raise ValueError("依赖子模块必须完整初始化并匹配精确 gitlink")
        sources.append(path / relative)
    for source in sources:
        alternate = Path(git(source, "rev-parse", "--git-path", "objects/info/alternates"))
        if not alternate.is_absolute():
            alternate = source / alternate
        if alternate.exists() or alternate.is_symlink():
            raise ValueError("依赖不能通过 alternates 借用其他仓库对象")
        if git(source, "rev-parse", "--show-toplevel") != str(source.resolve()):
            raise ValueError("依赖子来源未独立初始化")
        if git(source, "rev-parse", "--is-shallow-repository") != "false":
            raise ValueError("依赖必须保有完整历史与提交对象")
        for line in git(source, "config", "--list").splitlines():
            key, _, value = line.partition("=")
            if key == "extensions.partialclone" or (key.startswith("remote.") and
                    key.endswith((".promisor", ".partialclonefilter"))):
                raise ValueError("依赖不能使用 partial clone")
            if key in ("core.sparsecheckout", "core.sparsecheckoutcone") and value.lower() in (
                    "true", "yes", "on", "1"):
                raise ValueError("依赖不能使用 sparse checkout")
        git(source, "fsck", "--connectivity-only", "--no-dangling")


def stream_sha256(stream) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_host_archive(path: Path, entry: dict, *, download: bool) -> None:
    # 正式归档摘要与从精确 Git 源重建的归档必须同时匹配；不保留第二份来源缓存。
    version = entry["version"]
    expected_url = (entry["repository"][:-4] + f"/releases/download/v{version}/"
                    f"mbedtls-{version}-actions-exit.tar.bz2")
    if not re.fullmatch(r"[0-9a-f]{64}", entry["archive_sha256"]) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", version) or entry["archive_url"] != expected_url:
        raise ValueError("host Mbed TLS 必须锁定正式完整源归档")
    if download:
        with urllib.request.urlopen(entry["archive_url"], timeout=180) as response:
            digest = stream_sha256(response)
        if digest != entry["archive_sha256"]:
            raise ValueError("正式 host Mbed TLS 归档摘要与 quic-lock.json 不符")
    with tempfile.TemporaryDirectory(prefix="esp-frp-host-source-") as directory:
        archive = Path(directory) / "source.tar.bz2"
        subprocess.run([sys.executable, str(path / "tools/package_source_archive.py"),
                        "--output", str(archive)], check=True, capture_output=True, text=True,
                       timeout=180)
        with archive.open("rb") as stream:
            rebuilt = stream_sha256(stream)
    if rebuilt != entry["archive_sha256"]:
        raise ValueError("精确 Git 源与完整 host 发布归档内容不一致")

def prepare(path: Path, entry: dict) -> None:
    path.mkdir(parents=True, exist_ok=False)
    git(path, "init", "-q")
    git(path, "remote", "add", "origin", entry["repository"])
    git(path, "fetch", "origin", entry["revision"])
    git(path, "checkout", "--detach", "FETCH_HEAD")
    git(path, "submodule", "update", "--init", "--recursive", "--checkout",
        "--no-recommend-shallow")
    verify(path, entry)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("--ngtcp2-path", type=Path)
    parser.add_argument("--picotls-path", type=Path)
    parser.add_argument("--host-mbedtls-path", type=Path, help="可选的完整生成 host 4.1.0 来源")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK_PATH.read_text())
        if lock["schema_version"] != 1:
            raise ValueError("不支持的依赖锁")
        if bool(args.ngtcp2_path) != bool(args.picotls_path):
            raise ValueError("QUIC 必须同时提供 ngtcp2 与 Picotls 目录")
        entries = []
        if args.ngtcp2_path:
            entries.extend(((args.ngtcp2_path, lock["ngtcp2"]),
                            (args.picotls_path, lock["picotls"])))
        if args.host_mbedtls_path:
            entries.append((args.host_mbedtls_path, lock["host_mbedtls"]))
        if not entries:
            raise ValueError("至少提供 QUIC 源码组或完整 host 来源目录")
        for path, entry in entries:
            if not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]) or not re.fullmatch(
                    r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9-]+\.git", entry["repository"]):
                raise ValueError("依赖必须是精确公开 Git 提交")
            path = path.expanduser().absolute()
            if args.action == "prepare" and path.exists():
                raise ValueError("prepare 仅创建新目录；已有依赖使用 check")
        for path, entry in entries:
            path = path.expanduser().absolute()
            if args.action == "prepare":
                prepare(path, entry)
            else:
                verify(path, entry)
            if entry is lock["host_mbedtls"]:
                # check 独立重建并核锁定摘要，不依赖先前 prepare 成功或联网收据。
                verify_host_archive(path, entry, download=args.action == "prepare")
        if not args.quiet:
            print("ESP FRP QUIC 依赖\n  结果  精确源码已验证\n"
                  + "\n".join(f"  {path.name} {entry['revision']}" for path, entry in entries))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"ESP FRP QUIC 依赖\n  结果  失败\n  原因  {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())

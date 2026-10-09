"""用真实 checkout 核对 host 来源检查独立验证发布归档。"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("quic_sources", Path(__file__).parents[1] / "quic_sources.py")
SOURCES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCES)


class HostSourceContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        (self.source / "tools").mkdir(parents=True)
        self.git(self.source, "init", "-q", "-b", "master")
        self.git(self.source, "config", "user.name", "host source fixture")
        self.git(self.source, "config", "user.email", "host@example.invalid")
        self.content = b"complete generated source fixture\n"
        (self.source / "source.c").write_bytes(self.content)
        (self.source / "tools/package_source_archive.py").write_text(
            "import argparse\nfrom pathlib import Path\n"
            "p=argparse.ArgumentParser(); p.add_argument('--output',type=Path)\n"
            "p.parse_args().output.write_bytes((Path(__file__).parents[1]/'source.c').read_bytes())\n"
        )
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "-qm", "fixture")
        self.entry = {
            "repository": "https://github.com/example/host-source.git",
            "revision": self.git(self.source, "rev-parse", "HEAD"),
            "version": "4.1.0",
            "archive_url": "https://github.com/example/host-source/releases/download/v4.1.0/mbedtls-4.1.0-actions-exit.tar.bz2",
            "archive_sha256": hashlib.sha256(self.content).hexdigest(),
        }
        self.lock = self.root / "lock.json"
        self.write_lock()

    @staticmethod
    def git(path, *args):
        return subprocess.run(["git", "-C", str(path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def write_lock(self):
        self.lock.write_text(json.dumps({"schema_version": 1, "host_mbedtls": self.entry}))

    def run_entry(self, action, source):
        with patch.object(SOURCES, "LOCK_PATH", self.lock), patch.object(
                sys, "argv", ["quic_sources.py", action, "--host-mbedtls-path", str(source), "--quiet"]), \
                contextlib.redirect_stderr(io.StringIO()) as error:
            result = SOURCES.main()
        return result, error.getvalue()

    def test_check_rebuilds_archive_without_network(self):
        with patch.object(SOURCES.urllib.request, "urlopen", side_effect=AssertionError("check must be offline")):
            result, error = self.run_entry("check", self.source)
        self.assertEqual((result, error), (0, ""))

    def test_check_rejects_lock_digest_not_matching_git_source(self):
        self.entry["archive_sha256"] = "0" * 64
        self.write_lock()
        result, error = self.run_entry("check", self.source)
        self.assertEqual(result, 1)
        self.assertIn("发布归档内容不一致", error)

    def test_failed_prepare_cannot_make_later_check_bypass_archive(self):
        self.entry["archive_sha256"] = "0" * 64
        self.write_lock()
        destination = self.root / "prepared"

        def prepare_from_local(path, entry):
            self.git(self.root, "clone", "-q", str(self.source), str(path))
            SOURCES.verify(path, entry)

        with patch.object(SOURCES, "prepare", side_effect=prepare_from_local), patch.object(
                SOURCES.urllib.request, "urlopen", return_value=io.BytesIO(b"invalid downloaded archive")):
            result, error = self.run_entry("prepare", destination)
        self.assertEqual(result, 1)
        self.assertIn("归档摘要", error)
        self.assertTrue(destination.is_dir())
        SOURCES.verify(destination, self.entry)
        result, error = self.run_entry("check", destination)
        self.assertEqual(result, 1)
        self.assertIn("发布归档内容不一致", error)

    def test_check_rejects_shared_clone_even_when_fsck_passes(self):
        shared = self.root / "shared"
        self.git(self.root, "clone", "-q", "--shared", str(self.source), str(shared))
        self.git(shared, "fsck", "--connectivity-only", "--no-dangling")
        result, error = self.run_entry("check", shared)
        self.assertEqual(result, 1)
        self.assertIn("alternates", error)


if __name__ == "__main__":
    unittest.main()

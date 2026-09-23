"""用真实 Git 仓验证 SDK 身份、gitlink 和脏工作树拒绝。"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("sdk", Path(__file__).parents[1] / "sdk.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class SDKContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "lwip"
        self.sdk = self.root / "sdk"
        for path in (self.source, self.sdk):
            path.mkdir()
            self.run_git(path, "init", "-q", "-b", "master")
            self.run_git(path, "config", "user.name", "SDK fixture")
            self.run_git(path, "config", "user.email", "sdk@example.invalid")
        (self.source / "tcp.c").write_text("upstream\n")
        self.commit(self.source)
        self.original = self.run_git(self.source, "rev-parse", "HEAD")
        self.run_git(self.sdk, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                     str(self.source), "components/lwip/lwip")
        (self.sdk / "sdk.c").write_text("sdk\n")
        self.commit(self.sdk)
        sdk_revision = self.run_git(self.sdk, "rev-parse", "HEAD")
        (self.source / "tcp.c").write_text("corrected\n")
        self.commit(self.source)
        fixed = self.run_git(self.source, "rev-parse", "HEAD")
        self.lwip = self.sdk / "components/lwip/lwip"
        self.run_git(self.lwip, "fetch", "-q", "origin")
        self.run_git(self.lwip, "checkout", "-q", "--detach", fixed)
        self.lock = {"idf": {"revision": sdk_revision},
                     "lwip": {"revision": fixed, "path": "components/lwip/lwip"}}

    def tearDown(self):
        self.temp.cleanup()

    def run_git(self, path, *args):
        result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit(self, path):
        self.run_git(path, "add", ".")
        self.run_git(path, "commit", "-q", "-m", "测试快照")

    def test_accepts_only_locked_gitlink(self):
        SDK.verify(self.sdk, self.lock)

    def test_rejects_original_lwip(self):
        self.run_git(self.lwip, "checkout", "-q", "--detach", self.original)
        with self.assertRaisesRegex(ValueError, "零窗口修正"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_dirty_lwip(self):
        (self.lwip / "tcp.c").write_text("unverified\n")
        with self.assertRaisesRegex(ValueError, "未提交"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_extra_sdk_change(self):
        (self.sdk / "sdk.c").write_text("unverified\n")
        with self.assertRaisesRegex(ValueError, "其他修改"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_staged_sdk_change(self):
        self.run_git(self.sdk, "add", "components/lwip/lwip")
        with self.assertRaisesRegex(ValueError, "索引"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_untracked_sdk_content(self):
        (self.sdk / "other.c").write_text("unverified\n")
        with self.assertRaisesRegex(ValueError, "其他修改"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_wrong_sdk_revision(self):
        self.lock["idf"]["revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "ESP-IDF 提交"):
            SDK.verify(self.sdk, self.lock)

    def test_prepare_never_overwrites_existing_path(self):
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "输出路径已存在"):
            SDK.prepare(self.sdk, self.lock)
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

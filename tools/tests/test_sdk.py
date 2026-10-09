"""用真实 Git 仓验证 SDK 身份、gitlink 和脏工作树拒绝。"""
import importlib.util
from pathlib import Path
import subprocess
import os
import shutil
from unittest.mock import patch
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

    def test_rejects_shallow_nested_source(self):
        self.run_git(self.lwip, "fetch", "-q", "--depth=1",
                     self.source.as_uri(), self.lock["lwip"]["revision"])
        self.assertEqual(self.run_git(self.lwip, "rev-parse", "--is-shallow-repository"), "true")
        with self.assertRaisesRegex(ValueError, "shallow"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_partial_nested_source(self):
        self.run_git(self.lwip, "config", "remote.origin.promisor", "true")
        with self.assertRaisesRegex(ValueError, "partial"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_sparse_nested_source(self):
        self.run_git(self.lwip, "config", "core.sparseCheckout", "true")
        with self.assertRaisesRegex(ValueError, "sparse"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_sparse_worktree_configuration(self):
        self.run_git(self.lwip, "config", "extensions.worktreeConfig", "true")
        self.run_git(self.lwip, "config", "--worktree", "core.sparseCheckout", "true")
        with self.assertRaisesRegex(ValueError, "sparse"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_missing_history_object(self):
        relative = "objects/" + self.original[:2] + "/" + self.original[2:]
        object_path = Path(self.run_git(self.lwip, "rev-parse", "--git-path", relative))
        if not object_path.is_absolute():
            object_path = self.lwip / object_path
        object_path.unlink()
        with self.assertRaisesRegex(ValueError, "对象不完整"):
            SDK.verify_complete_repository(self.lwip)

    def test_rejects_shared_nested_source_even_when_fsck_passes(self):
        shutil.rmtree(self.lwip)
        self.run_git(self.root, "clone", "-q", "--shared", str(self.source), str(self.lwip))
        self.run_git(self.lwip, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "alternates"):
            SDK.verify(self.sdk, self.lock)

    def test_rejects_symlinked_git_directory_even_when_fsck_passes(self):
        alias = self.root / "symlinked-git-directory"
        shutil.copytree(self.source, alias, ignore=shutil.ignore_patterns(".git"))
        (alias / ".git").symlink_to(self.source / ".git", target_is_directory=True)
        self.run_git(alias, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SDK.verify_complete_repository(alias)

    def test_rejects_unbound_gitfile_even_when_fsck_passes(self):
        alias = self.root / "unbound-gitfile"
        shutil.copytree(self.source, alias, ignore=shutil.ignore_patterns(".git"))
        (alias / ".git").write_text("gitdir: " + str(self.source / ".git") + "\n")
        self.run_git(alias, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SDK.verify_complete_repository(alias)

    def test_rejects_linked_worktree_even_when_fsck_passes(self):
        linked = self.root / "linked"
        self.run_git(self.source, "worktree", "add", "-q", "--detach", str(linked), "HEAD")
        try:
            self.run_git(linked, "fsck", "--connectivity-only", "--no-dangling")
            with self.assertRaisesRegex(ValueError, "linked"):
                SDK.verify_complete_repository(linked)
        finally:
            self.run_git(self.source, "worktree", "remove", str(linked))

    def test_rejects_symlinked_object_storage_even_when_fsck_passes(self):
        objects = self.source / ".git/objects"
        outside = self.root / "outside-objects"
        objects.rename(outside)
        objects.symlink_to(outside, target_is_directory=True)
        self.run_git(self.source, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "对象库"):
            SDK.verify_complete_repository(self.source)

    def test_rejects_ignored_dirty_recursive_submodule(self):
        sdk = self.root / "recursive-sdk"
        framework = self.root / "framework"
        for path in (sdk, framework):
            path.mkdir()
            self.run_git(path, "init", "-q", "-b", "master")
            self.run_git(path, "config", "user.name", "SDK fixture")
            self.run_git(path, "config", "user.email", "sdk@example.invalid")
        self.run_git(framework, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 str(self.source), "leaf")
        self.run_git(framework, "add", ".")
        self.run_git(framework, "commit", "-qm", "nested framework")
        for source, relative in ((self.source, "components/lwip/lwip"), (framework, "framework")):
            self.run_git(sdk, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                     str(source), relative)
        self.run_git(sdk, "add", ".")
        self.run_git(sdk, "commit", "-qm", "SDK fixture")
        sdk_revision = self.run_git(sdk, "rev-parse", "HEAD")
        (self.source / "tcp.c").write_text("corrected source\n")
        self.run_git(self.source, "add", ".")
        self.run_git(self.source, "commit", "-qm", "lwIP correction")
        corrected = self.run_git(self.source, "rev-parse", "HEAD")
        lwip = sdk / "components/lwip/lwip"
        self.run_git(lwip, "fetch", "-q", "origin")
        self.run_git(lwip, "checkout", "-q", "--detach", corrected)
        self.run_git(sdk, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--recursive")
        # submodule update resets lwIP; restore the single intentional override.
        self.run_git(lwip, "checkout", "-q", "--detach", corrected)
        lock = {"idf": {"revision": sdk_revision},
                "lwip": {"path": "components/lwip/lwip", "revision": corrected}}
        SDK.verify(sdk, lock)
        self.run_git(sdk, "config", "submodule.framework.ignore", "all")
        self.run_git(sdk / "framework", "config", "submodule.leaf.ignore", "all")
        (sdk / "framework/leaf/tcp.c").write_text("unverified source\n")
        with self.assertRaises(ValueError):
            SDK.verify(sdk, lock)

    def test_rejects_environment_alternate_objects(self):
        with patch.dict(os.environ, {"GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.source / '.git/objects')}):
            with self.assertRaisesRegex(ValueError, "alternate"):
                SDK.verify(self.sdk, self.lock)

    def test_rejects_environment_object_directory(self):
        with patch.dict(os.environ, {"GIT_OBJECT_DIRECTORY": str(self.source / '.git/objects')}):
            with self.assertRaisesRegex(ValueError, "alternate"):
                SDK.verify_complete_repository(self.sdk)

    def test_prepare_never_overwrites_existing_path(self):
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "输出路径已存在"):
            SDK.prepare(self.sdk, self.lock)
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

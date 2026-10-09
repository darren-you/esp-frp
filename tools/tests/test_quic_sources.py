"""用真实 checkout 核对 host 来源检查独立验证发布归档。"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
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

    def test_rejects_symlinked_git_directory_even_when_fsck_passes(self):
        alias = self.root / "symlinked-git-directory"
        shutil.copytree(self.source, alias, ignore=shutil.ignore_patterns(".git"))
        (alias / ".git").symlink_to(self.source / ".git", target_is_directory=True)
        self.git(alias, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SOURCES.verify(alias, self.entry)

    def test_rejects_unbound_gitfile_even_when_fsck_passes(self):
        alias = self.root / "unbound-gitfile"
        shutil.copytree(self.source, alias, ignore=shutil.ignore_patterns(".git"))
        (alias / ".git").write_text("gitdir: " + str(self.source / ".git") + "\n")
        self.git(alias, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SOURCES.verify(alias, self.entry)

    def test_rejects_linked_worktree_even_when_fsck_passes(self):
        linked = self.root / "linked"
        self.git(self.source, "worktree", "add", "-q", "--detach", str(linked), "HEAD")
        try:
            self.git(linked, "fsck", "--connectivity-only", "--no-dangling")
            with self.assertRaisesRegex(ValueError, "linked"):
                SOURCES.verify(linked, self.entry)
        finally:
            self.git(self.source, "worktree", "remove", str(linked))

    def test_rejects_symlinked_object_storage_even_when_fsck_passes(self):
        objects = self.source / ".git/objects"
        outside = self.root / "outside-objects"
        objects.rename(outside)
        objects.symlink_to(outside, target_is_directory=True)
        self.git(self.source, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "对象库"):
            SOURCES.verify(self.source, self.entry)

    def test_absorbed_recursive_sources_are_checked_even_when_ignored(self):
        framework = self.root / "framework"
        framework.mkdir()
        self.git(framework, "init", "-q", "-b", "master")
        self.git(framework, "config", "user.name", "host source fixture")
        self.git(framework, "config", "user.email", "host@example.invalid")
        self.git(framework, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 str(self.source), "leaf")
        self.git(framework, "add", ".")
        self.git(framework, "commit", "-qm", "nested source fixture")
        self.git(self.source, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 str(framework), "framework")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "-qm", "host source with framework")
        self.git(self.source, "-c", "protocol.file.allow=always", "submodule", "update",
                 "--init", "--recursive")
        self.entry["revision"] = self.git(self.source, "rev-parse", "HEAD")
        self.assertTrue((self.source / "framework/leaf/.git").is_file())
        SOURCES.verify(self.source, self.entry)
        self.git(self.source, "config", "submodule.framework.ignore", "all")
        self.git(self.source / "framework", "config", "submodule.leaf.ignore", "all")
        (self.source / "framework/leaf/source.c").write_text("unverified source\n")
        with self.assertRaises(ValueError):
            SOURCES.verify(self.source, self.entry)

    def test_check_rejects_shared_clone_even_when_fsck_passes(self):
        shared = self.root / "shared"
        self.git(self.root, "clone", "-q", "--shared", str(self.source), str(shared))
        self.git(shared, "fsck", "--connectivity-only", "--no-dangling")
        result, error = self.run_entry("check", shared)
        self.assertEqual(result, 1)
        self.assertIn("alternates", error)

    def test_rejects_external_separate_git_directory_with_worktree_binding(self):
        separate = self.root / "separate"
        outside = self.root / "separate.git"
        self.git(self.root, "clone", "-q", "--separate-git-dir=" + str(outside),
                 str(self.source), str(separate))
        self.git(separate, "config", "core.worktree", str(separate))
        self.assertEqual(self.git(separate, "status", "--porcelain"), "")
        self.git(separate, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SOURCES.verify(separate, self.entry)

    def test_rejects_git_environment_redirecting_metadata_and_worktree(self):
        alias = self.root / "environment-redirect"
        shutil.copytree(self.source, alias, ignore=shutil.ignore_patterns(".git"))
        with patch.dict(os.environ, {"GIT_DIR": str(self.source / ".git"),
                                    "GIT_WORK_TREE": str(alias)}):
            with self.assertRaisesRegex(ValueError, "Git 环境"):
                SOURCES.verify(alias, self.entry)

    def test_rejects_replace_ref_even_when_head_and_status_match(self):
        original = self.git(self.source, "rev-parse", "HEAD")
        filename = self.source / "source.c"
        original_bytes = filename.read_bytes()
        filename.write_text("int substituted_business;\n")
        self.git(self.source, "add", filename.name)
        self.git(self.source, "commit", "-qm", "different source fixture")
        replacement = self.git(self.source, "rev-parse", "HEAD")
        self.git(self.source, "replace", original, replacement)
        self.git(self.source, "checkout", "-q", "--detach", original)
        self.assertEqual(self.git(self.source, "rev-parse", "HEAD"), original)
        self.assertEqual(self.git(self.source, "status", "--porcelain"), "")
        self.assertEqual(filename.read_text(), "int substituted_business;\n")
        # The verifier's ordinary Git reads ignore replacement refs even before rejection.
        self.assertEqual(SOURCES.git(self.source, "show", "HEAD:" + filename.name).encode(),
                         original_bytes.rstrip(b"\n"))
        with self.assertRaises(ValueError):
            SOURCES.verify(self.source, self.entry)

    def test_rejects_grafts_even_when_fsck_passes(self):
        head = self.git(self.source, "rev-parse", "HEAD")
        (self.source / ".git/info/grafts").write_text(head + "\n")
        self.git(self.source, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "grafts"):
            SOURCES.verify(self.source, self.entry)

    def test_rejects_absorbed_metadata_outside_host_modules(self):
        self.git(self.source, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 str(self.source), "dependency")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "-qm", "host nested fixture")
        self.entry["revision"] = self.git(self.source, "rev-parse", "HEAD")
        dependency = self.source / "dependency"
        SOURCES.verify(self.source, self.entry)
        directory = Path(self.git(dependency, "rev-parse", "--absolute-git-dir"))
        outside = self.root / "outside-dependency.git"
        directory.rename(outside)
        (dependency / ".git").write_text("gitdir: " + str(outside) + "\n")
        self.git(self.root, "config", "--file", str(outside / "config"), "core.worktree", str(dependency))
        self.git(dependency, "fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "Git 元数据"):
            SOURCES.verify(self.source, self.entry)




import shlex
import sys
import zlib


class SourceIntegrityTest(unittest.TestCase):
    """真实磁盘字节、文件模式与元数据不能由 Git 的干净状态替代。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self._git("init", "-q", "-b", "master")
        self._git("config", "user.name", "来源完整性 fixture")
        self._git("config", "user.email", "source@example.invalid")
        self.good = b"int good;\n"
        self.evil = b"int evil;\n"
        self.filename = self.source / "source.c"
        self.filename.write_bytes(self.good)
        self.filename.chmod(0o644)
        self._commit()
        self._verify()

    def _run_git(self, *args, check=True):
        return subprocess.run(["git", "-C", str(self.source), *args], check=check,
                              capture_output=True, env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"})

    def _git(self, *args):
        return self._run_git(*args).stdout.decode().strip()

    def _commit(self):
        self._git("add", ".")
        self._git("commit", "-qm", "真实来源 fixture")
        self.head = self._git("rev-parse", "HEAD")

    def _verify(self):
        SOURCES.verify(self.source, {"revision": self.head})

    def _assert_rejected(self, *, metadata=False):
        if metadata:
            with self.assertRaisesRegex(ValueError, "Git 元数据"):
                self._verify()
        else:
            with self.assertRaises((ValueError, RuntimeError, subprocess.SubprocessError)):
                self._verify()

    def _assert_hidden_byte_divergence(self):
        self.assertEqual(self._git("rev-parse", "HEAD"), self.head)
        self.assertEqual(self._git("status", "--porcelain", "--untracked-files=normal",
                                   "--ignore-submodules=none"), "")
        self.assertEqual(self._run_git("cat-file", "blob", "HEAD:source.c").stdout, self.good)
        self.assertEqual(self.filename.read_bytes(), self.evil)
        self.assertEqual(self._run_git("diff", "--exit-code", "HEAD").returncode, 0)
        self._git("fsck", "--connectivity-only", "--no-dangling")

    def test_rejects_clean_filter_hiding_raw_source_change(self):
        command = shlex.join([sys.executable, "-c",
                              'import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b"int good;\\n")'])
        self._git("config", "filter.fixture.clean", command)
        self._git("config", "filter.fixture.smudge", "cat")
        (self.source / ".git/info/attributes").write_text("*.c filter=fixture\n")
        self.filename.write_bytes(self.evil)
        self._assert_hidden_byte_divergence()
        self.assertEqual(self._git("hash-object", "--path=source.c", "source.c"),
                         self._git("rev-parse", "HEAD:source.c"))
        self.assertNotEqual(self._git("hash-object", "--no-filters", "source.c"),
                            self._git("rev-parse", "HEAD:source.c"))
        self._assert_rejected()

    def test_rejects_skip_worktree_hiding_raw_source_change(self):
        self._git("update-index", "--skip-worktree", "source.c")
        self.filename.write_bytes(self.evil)
        self._assert_hidden_byte_divergence()
        self.assertEqual(self._git("ls-files", "-v", "--", "source.c"), "S source.c")
        self._assert_rejected()

    def test_rejects_assume_unchanged_hiding_raw_source_change(self):
        self._git("update-index", "--assume-unchanged", "source.c")
        self.filename.write_bytes(self.evil)
        self._assert_hidden_byte_divergence()
        self.assertEqual(self._git("ls-files", "-v", "--", "source.c"), "h source.c")
        self._assert_rejected()

    def test_rejects_executable_change_hidden_by_core_filemode(self):
        self.assertTrue(self._git("ls-tree", "HEAD", "--", "source.c").startswith("100644 "))
        self._git("config", "core.filemode", "false")
        self.filename.chmod(0o755)
        self.assertEqual(self._git("status", "--porcelain"), "")
        self.assertEqual(self.filename.read_bytes(), self.good)
        self.assertEqual(self._run_git("cat-file", "blob", "HEAD:source.c").stdout, self.good)
        self.assertEqual(self._git("rev-parse", "HEAD"), self.head)
        self.assertNotEqual(self.filename.stat().st_mode & 0o111, 0)
        self._assert_rejected()

    def _tracked_symlink(self):
        link = self.source / "link.c"
        link.symlink_to("source.c")
        self._commit()
        self.assertTrue(self._git("ls-tree", "HEAD", "--", "link.c").startswith("120000 "))
        self.assertEqual(self._run_git("cat-file", "blob", "HEAD:link.c").stdout, b"source.c")
        self._verify()
        self._git("update-index", "--skip-worktree", "link.c")
        return link

    def test_rejects_tracked_symlink_replaced_with_regular_file(self):
        link = self._tracked_symlink()
        link.unlink()
        link.write_bytes(b"source.c")
        self.assertFalse(link.is_symlink())
        self.assertEqual(link.read_bytes(), self._run_git("cat-file", "blob", "HEAD:link.c").stdout)
        self.assertEqual(self._git("status", "--porcelain"), "")
        self._assert_rejected()

    def test_rejects_tracked_symlink_target_change(self):
        link = self._tracked_symlink()
        (self.root / "other.c").write_bytes(self.evil)
        link.unlink()
        link.symlink_to("../other.c")
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../other.c")
        self.assertEqual(link.read_bytes(), self.evil)
        self.assertEqual(self._run_git("cat-file", "blob", "HEAD:link.c").stdout, b"source.c")
        self.assertEqual(self._git("status", "--porcelain"), "")
        self._assert_rejected()

    def test_rejects_tracked_parent_directory_symlinked_outside_source(self):
        nested = self.source / "nested"
        nested.mkdir()
        (nested / "source.c").write_bytes(self.good)
        self._commit()
        self._verify()
        self._git("update-index", "--skip-worktree", "nested/source.c")
        outside = self.root / "outside-source-directory"
        nested.rename(outside)
        nested.symlink_to(outside, target_is_directory=True)
        (self.source / ".git/info/exclude").write_text("/nested\n")
        self.assertTrue(nested.is_symlink())
        self.assertEqual((nested / "source.c").read_bytes(), self.good)
        self.assertEqual(self._run_git("cat-file", "blob", "HEAD:nested/source.c").stdout,
                         self.good)
        self.assertEqual(self._git("status", "--porcelain"), "")
        self.assertEqual(self._git("rev-parse", "HEAD"), self.head)
        self._assert_rejected()

    def _external_metadata_symlink(self, relative):
        metadata = self.source / ".git" / relative
        outside = self.root / ("outside-" + relative)
        is_directory = metadata.is_dir()
        original_bytes = None if is_directory else metadata.read_bytes()
        metadata.rename(outside)
        metadata.symlink_to(outside, target_is_directory=is_directory)
        self.assertTrue(metadata.is_symlink())
        self.assertEqual(metadata.resolve(), outside.resolve())
        if original_bytes is not None:
            self.assertEqual(outside.read_bytes(), original_bytes)
        # Git itself may fail for external HEAD/refs; the guard must reject the
        # metadata link explicitly before depending on such version-specific errors.
        self._assert_rejected(metadata=True)

    def test_rejects_external_index_metadata_symlink(self):
        self._external_metadata_symlink("index")

    def test_rejects_external_head_metadata_symlink(self):
        self._external_metadata_symlink("HEAD")

    def test_rejects_external_config_metadata_symlink(self):
        self._external_metadata_symlink("config")

    def test_rejects_external_refs_metadata_symlink(self):
        self._external_metadata_symlink("refs")

    def test_rejects_corrupt_head_blob_when_connectivity_fsck_passes(self):
        blob = self._git("rev-parse", "HEAD:source.c")
        path = self.source / ".git/objects" / blob[:2] / blob[2:]
        self.assertTrue(path.is_file())
        self.assertEqual(self._run_git("cat-file", "blob", blob).stdout, self.good)
        self._git("fsck", "--full", "--no-dangling")
        path.chmod(0o600)
        path.write_bytes(zlib.compress(b"blob " + str(len(self.evil)).encode() + b"\0" + self.evil))
        self.assertEqual(self.filename.read_bytes(), self.good)
        self.assertEqual(self._git("rev-parse", "HEAD"), self.head)
        self._git("fsck", "--connectivity-only", "--no-dangling")
        full = self._run_git("fsck", "--full", "--no-dangling", check=False)
        self.assertNotEqual(full.returncode, 0)
        self.assertIn(b"mismatch", full.stdout + full.stderr)
        self._assert_rejected()




class SourceObjectIntegrityTest(unittest.TestCase):
    """Git 返回的储存 OID 不能代替对象原始类型、长度和内容的独立校验。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name).resolve() / "source"
        self.source.mkdir()
        self._git("init", "-q", "-b", "master")
        self._git("config", "user.name", "对象原始字节 fixture")
        self._git("config", "user.email", "object@example.invalid")
        self.good = b"int good;\n"
        self.evil = b"int evil;\n"
        (self.source / "source.c").write_bytes(self.good)
        self._git("add", ".")
        self._git("commit", "-qm", "真实对象 fixture")
        self.head = self._git("rev-parse", "HEAD")
        self._verify()

    def _run_git(self, *args, check=True, input_bytes=None):
        return subprocess.run(["git", "-C", str(self.source), *args], check=check,
                              capture_output=True, input=input_bytes,
                              env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"})

    def _git(self, *args):
        return self._run_git(*args).stdout.decode().strip()

    def _verify(self):
        SOURCES.verify(self.source, {"revision": self.head})

    def _corrupt_blob_preserving_storage_oid(self, blob):
        path = self.source / ".git/objects" / blob[:2] / blob[2:]
        self.assertTrue(path.is_file())
        path.chmod(0o600)
        path.write_bytes(zlib.compress(b"blob " + str(len(self.evil)).encode() + b"\0" + self.evil))
        self.assertEqual(self._git("rev-parse", "HEAD"), self.head)
        self.assertEqual((self.source / "source.c").read_bytes(), self.good)
        self.assertEqual(self._run_git("cat-file", "blob", blob).stdout, self.evil)
        batch = self._run_git("cat-file", "--batch", input_bytes=(blob + "\n").encode()).stdout
        self.assertEqual(batch, blob.encode() + b" blob " + str(len(self.evil)).encode()
                         + b"\n" + self.evil + b"\n")
        self.assertNotEqual(self._run_git("hash-object", "--stdin", input_bytes=self.evil)
                            .stdout.decode().strip(), blob)
        self._git("fsck", "--connectivity-only", "--no-dangling")
        with self.assertRaisesRegex(ValueError, "对象原始字节与 OID 不符"):
            self._verify()

    def test_rejects_head_blob_even_when_cat_file_reports_original_storage_oid(self):
        blob = self._git("rev-parse", "HEAD:source.c")
        self.assertEqual(self._run_git("cat-file", "blob", blob).stdout, self.good)
        self._corrupt_blob_preserving_storage_oid(blob)

    def test_rejects_corrupt_dangling_blob_when_connectivity_fsck_passes(self):
        payload = b"unreferenced original object;\n"
        blob = self._run_git("hash-object", "-w", "--stdin", input_bytes=payload).stdout.decode().strip()
        reachable = self._git("rev-list", "--all", "--objects").splitlines()
        self.assertFalse(any(line.split()[0] == blob for line in reachable))
        self.assertEqual(self._run_git("cat-file", "blob", blob).stdout, payload)
        self._verify()
        self._corrupt_blob_preserving_storage_oid(blob)



class SparseConfigurationTest(unittest.TestCase):
    """Git 最终生效的布尔配置与实际完整源码共同决定是否接受来源。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.global_config = self.root / "global.gitconfig"
        self.global_config.write_text("")
        self.included_config = self.root / "included.gitconfig"
        self.environment = patch.dict(os.environ, {
            "GIT_CONFIG_GLOBAL": str(self.global_config), "GIT_CONFIG_NOSYSTEM": "1",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.source = self.root / "source"
        self.source.mkdir()
        self._git("init", "-q", "-b", "master")
        self._git("config", "user.name", "稀疏配置 fixture")
        self._git("config", "user.email", "sparse@example.invalid")
        (self.source / "source.c").write_text("int source;\n")
        (self.source / "omitted").mkdir()
        (self.source / "omitted/source.c").write_text("int complete;\n")
        self._git("add", ".")
        self._git("commit", "-qm", "完整来源 fixture")

    def _git(self, *args, check=True):
        return subprocess.run(["git", "-C", str(self.source), *args], check=check,
                              capture_output=True, text=True)

    def _set(self, key, value, *scope):
        self._git("config", *scope, key, value)

    def _verify(self):
        SOURCES.verify_complete_repository(self.source)

    def _effective_sparse(self):
        result = self._git("config", "--bool", "--get", "core.sparseCheckout", check=False)
        return result.returncode, result.stdout.strip()

    def _include(self, value):
        self.included_config.write_text("[core]\n\tsparseCheckout = " + value + "\n")
        self._set("include.path", str(self.included_config), "--local")

    def test_accepts_global_true_overridden_by_local_false(self):
        self._set("core.sparseCheckout", "true", "--global")
        self._set("core.sparseCheckout", "false", "--local")
        self.assertEqual(self._effective_sparse(), (0, "false"))
        self._verify()

    def test_rejects_global_false_overridden_by_local_true(self):
        self._set("core.sparseCheckout", "false", "--global")
        self._set("core.sparseCheckout", "true", "--local")
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def test_accepts_worktree_false_overriding_local_true(self):
        self._set("core.sparseCheckout", "true", "--local")
        self._set("extensions.worktreeConfig", "true", "--local")
        self._set("core.sparseCheckout", "false", "--worktree")
        self.assertEqual(self._effective_sparse(), (0, "false"))
        self._verify()

    def test_rejects_worktree_true_overriding_local_false(self):
        self._set("core.sparseCheckout", "false", "--local")
        self._set("extensions.worktreeConfig", "true", "--local")
        self._set("core.sparseCheckout", "true", "--worktree")
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def test_accepts_included_local_false_after_local_true(self):
        self._set("core.sparseCheckout", "true", "--local")
        self._include("false")
        self.assertEqual(self._effective_sparse(), (0, "false"))
        self._verify()

    def test_rejects_included_local_true_after_local_false(self):
        self._set("core.sparseCheckout", "false", "--local")
        self._include("true")
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def test_accepts_inactive_cone_mode_with_complete_source(self):
        self._set("core.sparseCheckout", "false", "--local")
        self._set("core.sparseCheckoutCone", "true", "--local")
        self.assertEqual(self._effective_sparse(), (0, "false"))
        self._verify()

    def test_rejects_invalid_effective_boolean(self):
        self._set("core.sparseCheckout", "invalid-boolean", "--local")
        self.assertNotEqual(self._effective_sparse()[0], 0)
        with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)) as raised:
            self._verify()
        detail = getattr(raised.exception, "stderr", "") or str(raised.exception)
        self.assertIn("sparse", detail.lower())

    def test_rejects_nonzero_numeric_effective_true(self):
        self._set("core.sparseCheckout", "2", "--local")
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def test_rejects_implicit_boolean_effective_true(self):
        config = self.source / ".git/config"
        with config.open("a") as output:
            output.write("[core]\n\tsparseCheckout\n")
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def _omit_tracked_source(self):
        self._git("sparse-checkout", "set", "--no-cone", "/source.c")
        self.assertTrue((self.source / "source.c").is_file())
        self.assertFalse((self.source / "omitted/source.c").exists())

    def test_rejects_actual_sparse_checkout(self):
        self._omit_tracked_source()
        self.assertEqual(self._effective_sparse(), (0, "true"))
        with self.assertRaisesRegex(ValueError, "sparse"):
            self._verify()

    def test_rejects_missing_raw_source_after_sparse_flag_disabled(self):
        self._omit_tracked_source()
        self._set("core.sparseCheckout", "false", "--worktree")
        self.assertEqual(self._effective_sparse(), (0, "false"))
        with self.assertRaises((ValueError, FileNotFoundError)):
            self._verify()


if __name__ == "__main__":
    unittest.main()

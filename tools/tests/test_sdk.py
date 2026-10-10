"""真实 Git 正反例验证唯一受管 SDK 派生；不访问设备或公开网络。"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sdk", Path(__file__).parents[1] / "sdk.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


class SDKContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "lwip-source"
        self.tlsf_source = self.root / "tlsf-source"
        self.sdk = self.root / "idf-source"
        self.recipe_source = self.root / "recipe-source"
        for path in (self.source, self.tlsf_source, self.sdk, self.recipe_source):
            path.mkdir()
            self.run_git(path, "init", "-q", "-b", "master")
            self.run_git(path, "config", "user.name", "SDK fixture")
            self.run_git(path, "config", "user.email", "sdk@example.invalid")
        (self.source / "tcp.c").write_text("official lwip\n")
        self.commit(self.source)
        self.original_lwip = self.run_git(self.source, "rev-parse", "HEAD")
        (self.tlsf_source / "tlsf.c").write_text("official tlsf\n")
        self.commit(self.tlsf_source)
        for source, relative in ((self.source, "components/lwip/lwip"),
                                 (self.tlsf_source, "components/heap/tlsf")):
            self.run_git(self.sdk, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                         str(source), relative)
        (self.sdk / "sdk.c").write_text("official idf\n")
        self.commit(self.sdk)
        sdk_revision = self.run_git(self.sdk, "rev-parse", "HEAD")
        self.tlsf = self.sdk / "components/heap/tlsf"
        self.tlsf_revision = self.run_git(self.tlsf, "rev-parse", "HEAD")
        (self.source / "tcp.c").write_text("corrected lwip\n")
        self.commit(self.source)
        fixed = self.run_git(self.source, "rev-parse", "HEAD")
        self.lwip = self.sdk / "components/lwip/lwip"
        self.run_git(self.lwip, "fetch", "-q", "origin")
        self.run_git(self.lwip, "checkout", "-q", "--detach", fixed)
        (self.sdk / "sdk.c").write_text("official idf plus approved capacity statistics\n")
        (self.tlsf / "tlsf.c").write_text("official tlsf plus approved capacity statistics\n")
        self.recipe = {
            "schema_version": 2,
            "idf": {"repository": "https://github.com/darren-you/esp-idf.git", "revision": sdk_revision},
            "lwip": {"repository": "https://github.com/darren-you/esp-lwip.git", "revision": fixed,
                     "path": "components/lwip/lwip"},
            "tlsf": {"path": "components/heap/tlsf", "revision": self.tlsf_revision},
            "managed_patches": [],
            "derivation_stamp": SDK.DERIVATION_STAMP,
        }
        self.resources = []
        for name, repo, relative in (("idf", self.sdk, "sdk.c"), ("tlsf", self.tlsf, "tlsf.c")):
            content = self.run_git(repo, "diff", "--binary", "--", relative).encode() + b"\n"
            resource_path = f"tools/sdk-patches/capacity-{name}.patch"
            resource = self.recipe_source / resource_path
            resource.parent.mkdir(parents=True, exist_ok=True)
            resource.write_bytes(content)
            declaration = {"repository": name, "path": resource_path, "sha256": SDK.digest(content),
                           "files": [{"path": relative,
                                      "before_sha256": SDK.digest(SDK.git_bytes(repo, "HEAD:" + relative)),
                                      "after_sha256": SDK.digest((repo / relative).read_bytes())}]}
            self.recipe["managed_patches"].append(declaration)
            self.resources.append((declaration, resource))
        self.recipe_bytes = encoded(self.recipe)
        (self.recipe_source / "sdk-lock.json").write_bytes(self.recipe_bytes)
        self.commit(self.recipe_source)
        self.lock = {"schema_version": 2, "idf": self.recipe["idf"], "lwip": self.recipe["lwip"],
                     "sdk_derivation": {"repository": SDK.RECIPE_REPOSITORY,
                                        "revision": self.run_git(self.recipe_source, "rev-parse", "HEAD"),
                                        "path": "sdk-lock.json", "sha256": SDK.digest(self.recipe_bytes)}}
        self.stamp = self.sdk / SDK.DERIVATION_STAMP
        self.stamp.write_bytes(self.recipe_bytes)

    def run_git(self, path, *args):
        result = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.rstrip("\n")

    def commit(self, path):
        self.run_git(path, "add", ".")
        self.run_git(path, "commit", "-q", "-m", "测试快照")

    def verify(self):
        SDK.verify(self.sdk, self.lock)

    def reject(self, message=None):
        with self.assertRaises(ValueError) if message is None else self.assertRaisesRegex(ValueError, message):
            self.verify()

    def replace_recipe(self, recipe):
        data = encoded(recipe)
        self.lock["sdk_derivation"]["sha256"] = SDK.digest(data)
        self.stamp.write_bytes(data)
        return data

    def pristine(self):
        self.run_git(self.sdk, "restore", "--", "sdk.c")
        self.run_git(self.tlsf, "restore", "--", "tlsf.c")
        self.stamp.unlink()

    def test_accepts_exact_derivation_and_locked_gitlink(self):
        self.verify()

    def test_check_never_fetches_or_executes_sdk_code(self):
        original = SDK.git
        def reads_only(path, *args):
            self.assertNotIn("fetch", args)
            self.assertNotIn("update", args)
            self.assertNotIn("apply", args)
            return original(path, *args)
        with patch.object(SDK, "git", reads_only), patch.object(SDK, "fetch_recipe", side_effect=AssertionError):
            self.verify()

    def test_rejects_original_lwip(self):
        self.run_git(self.lwip, "checkout", "-q", "--detach", self.original_lwip)
        self.reject("零窗口修正")

    def test_rejects_dirty_lwip(self):
        (self.lwip / "tcp.c").write_text("unverified\n")
        self.reject("未提交")

    def test_rejects_extra_sdk_change(self):
        (self.sdk / "other.c").write_text("unverified\n")
        self.reject("其他修改")

    def test_rejects_staged_sdk_change(self):
        self.run_git(self.sdk, "add", "sdk.c")
        self.reject("索引")

    def test_rejects_staged_tlsf_change(self):
        self.run_git(self.tlsf, "add", "tlsf.c")
        self.reject("索引")

    def test_rejects_untracked_tlsf_content(self):
        (self.tlsf / "other.c").write_text("unverified\n")
        self.reject("其他修改")

    def test_rejects_wrong_sdk_revision(self):
        self.lock["idf"] = dict(self.lock["idf"], revision="0" * 40)
        self.recipe["idf"] = self.lock["idf"]
        self.replace_recipe(self.recipe)
        self.reject("ESP-IDF")

    def test_rejects_wrong_tlsf_revision(self):
        self.recipe["tlsf"]["revision"] = "0" * 40
        self.replace_recipe(self.recipe)
        self.reject("TLSF")

    def test_rejects_missing_or_pristine_stamp(self):
        self.stamp.unlink()
        self.reject("普通文件")
        self.pristine_without_stamp()
        self.reject("普通文件")

    def pristine_without_stamp(self):
        self.run_git(self.sdk, "restore", "--", "sdk.c")
        self.run_git(self.tlsf, "restore", "--", "tlsf.c")

    def test_rejects_tampered_stamp(self):
        self.stamp.write_bytes(self.recipe_bytes + b"\n")
        self.reject("清单摘要")

    def test_rejects_stamp_symlink(self):
        original = self.root / "same-recipe.json"
        original.write_bytes(self.recipe_bytes)
        self.stamp.unlink(); self.stamp.symlink_to(original)
        self.reject("符号链接")

    def test_rejects_source_symlink_even_when_bytes_match(self):
        file = self.tlsf / "tlsf.c"
        source = self.root / "same-source.c"
        source.write_bytes(file.read_bytes())
        file.unlink(); file.symlink_to(source)
        # Git detects file-to-symlink type changes before the byte reader.
        self.reject()

    def test_rejects_partial_and_tampered_source(self):
        self.run_git(self.sdk, "restore", "--", "sdk.c")
        self.reject("其他修改")
        (self.sdk / "sdk.c").write_text("tampered\n")
        self.reject("源码摘要")

    def test_rejects_forged_official_before_hash(self):
        self.recipe["managed_patches"][0]["files"][0]["before_sha256"] = "0" * 64
        self.replace_recipe(self.recipe)
        self.reject("官方原文摘要")

    def test_rejects_other_submodule_version_drift(self):
        (self.tlsf / "tlsf.c").write_text("different committed allocator\n")
        self.commit(self.tlsf)
        self.reject("TLSF")

    def test_rejects_uninitialized_tlsf(self):
        self.run_git(self.sdk, "submodule", "deinit", "-f", "components/heap/tlsf")
        self.reject("TLSF")

    def test_rejects_unknown_recipe_fields_and_duplicate_json(self):
        self.recipe["unknown_allowlist"] = ["anything"]
        self.replace_recipe(self.recipe)
        self.reject("字段")
        data = self.recipe_bytes.replace(b'{\n', b'{\n  "schema_version": 2,\n', 1)
        self.lock["sdk_derivation"]["sha256"] = SDK.digest(data)
        self.stamp.write_bytes(data)
        self.reject("重复字段")

    def test_rejects_duplicate_patch_or_path_escape(self):
        self.recipe["managed_patches"][1]["repository"] = "idf"
        self.replace_recipe(self.recipe)
        self.reject("修改仓库")
        self.recipe["managed_patches"][1]["repository"] = "tlsf"
        self.recipe["managed_patches"][0]["files"][0]["path"] = "../escaped.c"
        self.replace_recipe(self.recipe)
        self.reject("相对路径")

    def test_prepare_never_overwrites_existing_path(self):
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "输出路径已存在"):
            SDK.prepare(self.sdk, self.lock)
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)

    def test_prepare_rejects_dangling_output_symlink(self):
        output = self.root / "dangling"
        output.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "输出路径已存在"):
            SDK.prepare(output, self.lock)
        self.assertTrue(output.is_symlink())

    def test_apply_exact_recipe_from_pristine_real_git(self):
        self.pristine()
        SDK.apply_recipe(self.sdk, self.lock, self.recipe_bytes, self.recipe, self.resources)
        self.verify()
        self.assertEqual(self.stamp.read_bytes(), self.recipe_bytes)
        self.assertEqual(self.stamp.stat().st_mode & 0o777, 0o600)

    def test_apply_checks_every_patch_before_any_mutation(self):
        self.pristine()
        resource = self.resources[1][1]
        resource.write_bytes(resource.read_bytes() + b"corrupt\n")
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "输入摘要"):
            SDK.apply_recipe(self.sdk, self.lock, self.recipe_bytes, self.recipe, self.resources)
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)
        self.assertFalse(self.stamp.exists())

    def test_apply_rejects_recipe_hash_before_mutation(self):
        self.pristine()
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "清单摘要"):
            SDK.apply_recipe(self.sdk, self.lock, self.recipe_bytes + b"\n", self.recipe, self.resources)
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)
        self.assertFalse(self.stamp.exists())

    def test_apply_rejects_incomplete_resource_set_before_mutation(self):
        self.pristine()
        before = (self.sdk / "sdk.c").read_bytes()
        with self.assertRaisesRegex(ValueError, "输入集合"):
            SDK.apply_recipe(self.sdk, self.lock, self.recipe_bytes, self.recipe, self.resources[:1])
        self.assertEqual((self.sdk / "sdk.c").read_bytes(), before)
        self.assertFalse(self.stamp.exists())

    def test_recipe_lock_rejects_old_schema_or_other_source(self):
        path = self.root / "component-lock.json"
        path.write_bytes(encoded(self.lock))
        with patch.object(SDK, "LOCK_PATH", path):
            self.assertEqual(SDK.read_lock(), self.lock)
            invalid = dict(self.lock, schema_version=1)
            path.write_bytes(encoded(invalid))
            with self.assertRaisesRegex(ValueError, "旧 SDK 锁"):
                SDK.read_lock()
            invalid = copy.deepcopy(self.lock)
            invalid["sdk_derivation"]["repository"] = "https://github.com/example/other.git"
            path.write_bytes(encoded(invalid))
            with self.assertRaisesRegex(ValueError, "唯一 recipe"):
                SDK.read_lock()

    def test_full_prepare_uses_exact_git_sources_and_never_runs_base(self):
        output = self.root / "new-sdk"
        original = SDK.git
        sources = {self.lock["idf"]["repository"]: str(self.sdk),
                   self.lock["lwip"]["repository"]: str(self.source),
                   self.lock["sdk_derivation"]["repository"]: str(self.recipe_source)}
        fetches = []
        def local_git(path, *args):
            items = list(args)
            if items[:2] in (["remote", "add"], ["remote", "set-url"]):
                if items[-1] in sources:
                    items[-1] = sources[items[-1]]
            if items and items[0] == "submodule" and "update" in items:
                items = ["-c", "protocol.file.allow=always", *items]
            if items and items[0] == "fetch":
                fetches.append(items[-1])
            self.assertNotIn("submodule", items if path.name == "recipe" else [])
            return original(path, *items)
        with patch.object(SDK, "git", local_git):
            SDK.prepare(output, self.lock)
            SDK.verify(output, self.lock)
        self.assertEqual(fetches, [self.lock["sdk_derivation"]["revision"],
                                   self.lock["idf"]["revision"], self.lock["lwip"]["revision"]])
        self.assertEqual((output / SDK.DERIVATION_STAMP).read_bytes(), self.recipe_bytes)
        self.assertFalse((output / "tools/sdk-patches").exists())
        self.assertFalse((output / "tools/prepare_sdk.py").exists())


if __name__ == "__main__":
    unittest.main()

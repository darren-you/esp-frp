#!/usr/bin/env python3
"""在固定官方模块的临时副本加入纯测试；不修改官方源树或运行配置。"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent
MODULE = "github.com/fatedier/frp"
VERSION = "v0.71.0"


def run(*args: str, capture: bool = False, cwd: Path = ROOT) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ""


def main() -> None:
    module = json.loads(run("go", "list", "-mod=readonly", "-m", "-json", MODULE, capture=True))
    if module.get("Version") != VERSION or "Replace" in module:
        raise SystemExit("官方 fixture 必须读取未替换的 FRP v0.71.0")
    run("go", "mod", "verify")
    with tempfile.TemporaryDirectory(prefix="esp-frp-xtcp-official-") as directory:
        # Copy the verified official module into a temporary test workspace.
        # Only extra test files are added; upstream implementation stays exact.
        source = Path(directory) / "official"
        shutil.copytree(module["Dir"], source)
        extra_tests = {
            str(source / "client/proxy/esp_frp_xtcp_binding_test.go"): str(ROOT / "fixtures/provider_test.go.txt"),
            str(source / "pkg/nathole/esp_frp_xtcp_binding_test.go"): str(ROOT / "fixtures/controller_test.go.txt"),
        }
        for target, fixture in extra_tests.items():
            Path(target).parent.chmod(0o755)
            shutil.copyfile(fixture, target)
        run("go", "test", "-mod=readonly", "-count=1", "-v", ".")
        listed = run("go", "test", "-mod=readonly", "-list", "^TestESPFRPFixedOfficial",
                     "./client/proxy", "./pkg/nathole", cwd=source, capture=True)
        for name in ("ProviderAcceptsUnrelatedUDPSource", "ActualVisitorSkipsAllowUsers", "ClientSIDDoesNotBindProxy"):
            if "TestESPFRPFixedOfficial" + name not in listed:
                raise SystemExit("官方 fixture 未装配: " + name)
        run("go", "test", "-mod=readonly", "-count=1", "-run", "^TestESPFRPFixedOfficial",
            "-v", "./client/proxy", "./pkg/nathole", cwd=source)


if __name__ == "__main__":
    main()

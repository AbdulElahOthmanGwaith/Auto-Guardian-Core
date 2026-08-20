"""اختبارات منخفضة المخاطر لمنطق verify.py."""

import json
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

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

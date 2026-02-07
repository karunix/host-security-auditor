import os
from auditor.checks import check_world_writable_files
from auditor.models import Severity


def test_detects_world_writable_file(tmp_path):
    insecure_file = tmp_path / "bad.conf"
    insecure_file.write_text("test")

    # rw-rw-rw-
    os.chmod(insecure_file, 0o666)

    findings = check_world_writable_files(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "world-writable" in findings[0].observation.lower()


def test_no_world_writable_files(tmp_path):
    secure_file = tmp_path / "good.conf"
    secure_file.write_text("secure")

    # rw-r--r--
    os.chmod(secure_file, 0o644)

    findings = check_world_writable_files(tmp_path)

    assert findings == []

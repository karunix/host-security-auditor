import os
from auditor.checks import check_sensitive_file_permissions
from auditor.models import Severity


def test_detects_insecure_passwd_permissions(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash")

    # Too permissive: rw-rw-r--
    os.chmod(passwd, 0o664)

    findings = check_sensitive_file_permissions(
        base_path=tmp_path,
        files={
            "passwd": 0o644,
        },
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "passwd" in findings[0].observation


def test_detects_insecure_shadow_permissions(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text("root:*:19000:0:99999:7:::")

    # Too permissive: rw-r--r--
    os.chmod(shadow, 0o644)

    findings = check_sensitive_file_permissions(
        base_path=tmp_path,
        files={
            "shadow": 0o640,
        },
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "shadow" in findings[0].observation


def test_secure_permissions_produce_no_findings(tmp_path):
    passwd = tmp_path / "passwd"
    shadow = tmp_path / "shadow"

    passwd.write_text("root:x:0:0:root:/root:/bin/bash")
    shadow.write_text("root:*:19000:0:99999:7:::")

    os.chmod(passwd, 0o644)
    os.chmod(shadow, 0o640)

    findings = check_sensitive_file_permissions(
        base_path=tmp_path,
        files={
            "passwd": 0o644,
            "shadow": 0o640,
        },
    )

    assert findings == []

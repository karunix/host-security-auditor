import os
from auditor.models import Finding, Severity


def check_world_writable_files(path):
    findings = []

    for root, _, files in os.walk(path):
        for name in files:
            file_path = os.path.join(root, name)

            try:
                st = os.stat(file_path)
            except OSError:
                # Skip files we cannot stat
                continue

            # Check "world-writable" bit
            if st.st_mode & 0o002:
                findings.append(
                    Finding(
                        scope="Filesystem permissions",
                        observation=f"World-writable file found: {file_path}",
                        severity=Severity.HIGH,
                        explanation=(
                            "World-writable files allow any local user to "
                            "modify them, which can lead to privilege escalation."
                        ),
                        recommendation=(
                            "Restrict permissions so only the owner (or root) "
                            "can write to this file."
                        ),
                    )
                )

    return findings
import os
from auditor.models import Finding, Severity


def check_sensitive_file_permissions(base_path, files):
    """
    Check permissions of sensitive files.

    :param base_path: Directory containing the files (e.g. /etc or tmp_path in tests)
    :param files: dict of filename -> max allowed mode (e.g. {"passwd": 0o644})
    """
    findings = []

    for filename, max_mode in files.items():
        file_path = os.path.join(base_path, filename)

        if not os.path.exists(file_path):
            # Missing files are handled by other checks later
            continue

        try:
            st = os.stat(file_path)
        except OSError:
            continue

        actual_mode = st.st_mode & 0o777

        if actual_mode > max_mode:
            findings.append(
                Finding(
                    scope="Filesystem permissions",
                    observation=(
                        f"Insecure permissions on {filename}: "
                        f"{oct(actual_mode)} (expected {oct(max_mode)} or stricter)"
                    ),
                    severity=Severity.HIGH,
                    explanation=(
                        f"The file {filename} contains sensitive account information. "
                        "Overly permissive permissions may allow unauthorized access."
                    ),
                    recommendation=(
                        f"Restrict permissions on {filename} to {oct(max_mode)} "
                        "or more restrictive."
                    ),
                )
            )

    return findings

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

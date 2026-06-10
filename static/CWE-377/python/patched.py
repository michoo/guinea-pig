# Remediation for CWE-377: Insecure Temporary File
# Fix: Create the temp file atomically with NamedTemporaryFile to avoid the TOCTOU race.

import tempfile


def write_temp(data):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".dat", delete=False
    ) as f:
        f.write(data)
        return f.name

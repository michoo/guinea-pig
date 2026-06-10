# CWE-377: Insecure Temporary File
# A temporary file name is generated with mktemp, creating a race condition (TOCTOU).
# Vulnerable sink: tempfile.mktemp()

import tempfile


def write_temp(data):
    tmp_path = tempfile.mktemp(suffix=".dat")
    with open(tmp_path, "w") as f:
        f.write(data)
    return tmp_path

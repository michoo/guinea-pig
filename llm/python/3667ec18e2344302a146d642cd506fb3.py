import tempfile


def write_temp(data):
    tmp_path = tempfile.mktemp(suffix=".dat")
    with open(tmp_path, "w") as f:
        f.write(data)
    return tmp_path

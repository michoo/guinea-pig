// Remediation for CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
// Fix: Open atomically with O_CREAT|O_EXCL|O_NOFOLLOW instead of checking access() then opening.

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    const char* path = argv[1];
    // Single atomic open: O_EXCL fails if the file exists, O_NOFOLLOW rejects symlinks.
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        write(fd, "trusted data\n", 13);
        close(fd);
    }
    return 0;
}

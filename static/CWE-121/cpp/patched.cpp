// Remediation for CWE-121: Stack-based Buffer Overflow
// Fix: Replace sprintf with snprintf bounded by the destination buffer size.

#include <cstdio>

int main(int argc, char** argv) {
    char dest[16];
    if (argc < 2) {
        return 1;
    }
    // snprintf never writes past sizeof(dest); output is truncated and NUL-terminated.
    snprintf(dest, sizeof(dest), "user=%s", argv[1]);
    printf("%s\n", dest);
    return 0;
}

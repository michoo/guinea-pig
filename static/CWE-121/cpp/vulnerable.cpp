// CWE-121: Stack-based Buffer Overflow
// Formats attacker-controlled input into a small stack buffer with no size limit.
// Vulnerable sink: sprintf()

#include <cstdio>

int main(int argc, char** argv) {
    char dest[16];
    if (argc < 2) {
        return 1;
    }
    // sprintf has no bounds: a long argv[1] overflows the 16-byte stack buffer.
    sprintf(dest, "user=%s", argv[1]);
    printf("%s\n", dest);
    return 0;
}

// CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
// Copies attacker-controlled argv data into a fixed-size stack buffer without bounds checking.
// Vulnerable sink: strcpy()

#include <cstring>
#include <cstdio>

int main(int argc, char** argv) {
    char buffer[32];
    if (argc < 2) {
        return 1;
    }
    // No length check: argv[1] may exceed 32 bytes and overflow the buffer.
    strcpy(buffer, argv[1]);
    printf("Copied: %s\n", buffer);
    return 0;
}

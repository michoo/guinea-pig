// Remediation for CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
// Fix: Use std::string to hold the input so the copy grows safely instead of overflowing a fixed buffer.

#include <string>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    // std::string allocates as needed; no fixed-size stack buffer to overflow.
    std::string buffer = argv[1];
    printf("Copied: %s\n", buffer.c_str());
    return 0;
}

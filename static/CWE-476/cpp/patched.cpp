// Remediation for CWE-476: NULL Pointer Dereference
// Fix: Check the allocation result for null before dereferencing the pointer.

#include <cstdlib>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    size_t n = (size_t)atoll(argv[1]);
    if (n < 5) {
        n = 5;
    }
    char* p = (char*)malloc(n);
    // Verify malloc succeeded before writing through the pointer.
    if (!p) {
        return 1;
    }
    strncpy(p, "data", n - 1);
    p[n - 1] = '\0';
    printf("%s\n", p);
    free(p);
    return 0;
}

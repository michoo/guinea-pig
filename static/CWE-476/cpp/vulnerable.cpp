// CWE-476: NULL Pointer Dereference
// Dereferences a pointer returned by an allocation/lookup that can be null.
// Vulnerable sink: dereference of possibly-null pointer

#include <cstdlib>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    size_t n = (size_t)atoll(argv[1]);
    char* p = (char*)malloc(n);
    // malloc may return NULL; no check before dereferencing.
    p[0] = 'A';
    strcpy(p, "data");
    printf("%s\n", p);
    return 0;
}

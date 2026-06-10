// CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
// Checks access permission on a path, then opens it for writing, allowing a swap in between.
// Vulnerable sink: access() check followed by fopen() write

#include <cstdio>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    const char* path = argv[1];
    // Time-of-check: the path may be replaced (symlink) before the open below.
    if (access(path, W_OK) == 0) {
        // Time-of-use: opens whatever path now points to.
        FILE* f = fopen(path, "w");
        if (f) {
            fputs("trusted data\n", f);
            fclose(f);
        }
    }
    return 0;
}

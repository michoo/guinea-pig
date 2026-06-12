#include <cstdio>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    const char* path = argv[1];
    if (access(path, W_OK) == 0) {
        FILE* f = fopen(path, "w");
        if (f) {
            fputs("trusted data\n", f);
            fclose(f);
        }
    }
    return 0;
}

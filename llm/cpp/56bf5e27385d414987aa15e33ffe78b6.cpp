#include <cstdio>

int main(int argc, char** argv) {
    char dest[16];
    if (argc < 2) {
        return 1;
    }
    sprintf(dest, "user=%s", argv[1]);
    printf("%s\n", dest);
    return 0;
}

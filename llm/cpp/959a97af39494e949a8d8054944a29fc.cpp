#include <cstdlib>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    size_t n = (size_t)atoll(argv[1]);
    char* p = (char*)malloc(n);
    p[0] = 'A';
    strcpy(p, "data");
    printf("%s\n", p);
    return 0;
}

#include <cstdlib>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    unsigned int count = (unsigned int)atoi(argv[1]);
    int* data = (int*)malloc(count * sizeof(long long));
    memset(data, 0, count * sizeof(long long));
    free(data);
    return 0;
}

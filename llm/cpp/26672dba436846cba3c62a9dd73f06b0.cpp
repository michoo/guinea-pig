#include <cstdlib>
#include <cstdio>

int main() {
    char* buf = (char*)malloc(64);
    if (!buf) {
        return 1;
    }
    free(buf);
    free(buf);
    printf("done\n");
    return 0;
}

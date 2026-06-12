#include <cstdlib>
#include <cstring>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", argv[1]);
    system(cmd);
    return 0;
}

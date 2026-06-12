#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    char* message = argv[1];
    printf(message);
    return 0;
}

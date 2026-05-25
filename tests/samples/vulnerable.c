#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_arg(char *input) {
    char buffer[16];
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_arg(argv[1]);
        system(argv[1]);
    }
    return 0;
}

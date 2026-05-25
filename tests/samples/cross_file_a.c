#include <stdio.h>

void run_command(char *cmd);

int main(int argc, char **argv) {
    if (argc > 1) {
        run_command(argv[1]);
    }
    return 0;
}

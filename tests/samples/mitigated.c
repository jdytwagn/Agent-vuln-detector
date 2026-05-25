#include <stdio.h>
#include <string.h>

void safe_copy(char *input) {
    char buffer[16];
    if (strlen(input) < sizeof(buffer)) {
        strcpy(buffer, input);
    }
}

void safer_format(char *input) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s", input);
}

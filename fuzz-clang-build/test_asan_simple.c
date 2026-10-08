#include <stdlib.h>
int main(void) {
    int *p = (int*)malloc(4 * sizeof(int));
    p[4] = 0;  /* heap buffer overflow */
    free(p);
    return 0;
}
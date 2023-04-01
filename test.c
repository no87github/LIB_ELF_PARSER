#include <stdio.h>
#include <unistd.h>

int global = 10;

int main(void)
{
    while (1)
    {
        printf("Hello %d\n", global);
        sleep(10);
    }

    return 0;
}
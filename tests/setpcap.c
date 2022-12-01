#include <linux/capability.h>
#include <sys/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


int main(int argc, char *argv[])
{
    FILE *f = fopen("/proc/self/status", "r");

    char buf[1024];
    printf("TESTING CAPABILITIES\n");
    while (fgets(buf, 1024, f)) {
        if (strstr(buf, "Cap")) {
            printf("%s", buf);
        }
    }
    return 0;
}

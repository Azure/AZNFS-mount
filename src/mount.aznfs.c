#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MOUNTSCRIPT "/opt/microsoft/aznfs/mountscript.sh"

int main(int argc, char *argv[])
{
    if (setreuid(0, 0) != 0)
    {
        perror("setreuid");
        return 1;
    }

    // Run "/opt/microsoft/aznfs/mountscript.sh" which will do original mount.
    execv(MOUNTSCRIPT, argv);
    perror("execv");
    return 1;
}
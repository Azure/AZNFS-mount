#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
    if (setreuid(0,0) != 0)
    {
        perror("setreuid failed!");
    }

    char arguments[50];
    strcpy(arguments, "/opt/microsoft/aznfs/mountscript.sh ");
    
    for (int i = 1; i < argc; i++)
    {
        strcat(arguments, argv[i]);
        if (i != argc-1)
        {
            strcat(arguments, " ");
        }
    }

    // Run "/opt/microsoft/aznfs/mountscript.sh" which will do original mount.
    system(arguments);
    return 0;
}

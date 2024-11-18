// --------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MOUNTSCRIPT "/opt/microsoft/aznfs/mountscript.sh"

int main(int argc, char *argv[])
{
    unsetenv("BASH_ENV");
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
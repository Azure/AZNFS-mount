// --------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MOUNTSCRIPT "/opt/microsoft/aznfs/mountscript.sh"

int main(int argc, char *argv[])
{
    unsetenv("BASH_ENV");
    unsetenv("LD_PRELOAD");

    /*
     * This program is setuid root, so the caller fully controls the environment
     * we are about to hand to the mount script running as root. The log
     * directory overrides make the script create and write files at a path of
     * the caller's choosing, which an unprivileged user could point at an
     * arbitrary location or a symlink. Drop them here, the log directory is
     * configured by the administrator in /opt/microsoft/aznfs/data/config.
     */
    unsetenv("AZNFS_LOGDIR");
    unsetenv("AZNFSC_LOGDIR");

    /*
     * umask is inherited too, and every file the script then creates as root
     * takes it. Under "umask 000" that means world writable logs, and any
     * staged file the caller can win a race on. Not inherited from the caller.
     */
    umask(0022);

    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
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
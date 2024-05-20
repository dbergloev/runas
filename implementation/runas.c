#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

// Internal headers
#include "runas.h"
#include "common.h"
#include "authenticate.h"

/**
 *
 */
static bool isdigits(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) {
            return false;
        }
    }
    
    return true;
}

/**
 *
 */
static bool parseuid(const char *user, uid_t *uid) {
    struct passwd *pw;
    char *endptr;
    
    if (isdigits(user) == true) {
        *uid = (uid_t) strtoul(user, &endptr, 10);
        
        if (*endptr != '\0' || *uid == ULONG_MAX) { // Make sure that it reached the end
            return false;
        }
    
        // Even though we have a UID, we validate it.
        pw = getpwuid(*uid);
    
    } else {
        pw = getpwnam(user);
    }
    
    if (!pw) {
        return false;
    }
    
    *uid = pw->pw_uid;
    
    return true;
}

/**
 *
 */
static bool validategid(const char *group) {
    struct group *gr;
    char *endptr;
    gid_t gid;
    
    if (isdigits(group) == true) {
        gid = (gid_t) strtoul(group, &endptr, 10);
        
        if (*endptr != '\0' || gid == ULONG_MAX) { // Make sure that it reached the end
            return false;
        }
    
        // Even though we have a GID, we validate it.
        gr = getgrgid(gid);
    
    } else {
        gr = getgrnam(group);
    }
    
    if (!gr) {
        return false;
    }
    
    return true;
}

/**
 *
 */
static void usage() {
    printf("Usage: runas [-u username] command [arguments]\n\n");
    printf("  -s, --shell             Run $SHELL as the target user\n");
    printf("  -u, --user   USER       Run process as the specified user name or ID\n");
    printf("  -g, --group  GROUP      Run process as the specified group name or ID\n");
    printf("  -h, --help              Display this help screen\n");
    printf("      --env    VAR=VAL    Set environment variable\n");
    printf("  -n, --non-interactive   Non-interactive mode, don't prompt for password\n");
    printf("  -S, --stdin             Read password from standard input\n");
    printf("  -v, --version           Display version information and exit\n");
    printf("  --                      Stop processing command line arguments\n");
}

/**
 *
 */
struct option argv_options[] = {
    {"user", required_argument, '\0', 'u'},
    {"shell", no_argument, '\0', 's'},
    {"help", no_argument, '\0', 'h'},
    {"non-interactive", no_argument, '\0', 'n'},
    {"stdin", no_argument, '\0', 'S'},
    {"version", no_argument, '\0', 'v'},
    {"env", required_argument, '\0', 0},
    {'\0', 0, '\0', 0}
};

/**
 * WITHOUT_EXPAND_ENV will remove the --expand-environment option 
 * which will then support systemd versions between 240 and 253.
 * This option was first introduced in 254.
 */
char *run_argv_args[] = {
    "systemd-run",
    "--quiet",
    "-G",
    "--send-sighup",
#ifndef WITHOUT_EXPAND_ENV
    "--expand-environment=false",
#endif
    "--uid", "0",  // MUST remain at the end
    '\0'
};

const int run_argc_args = sizeof(run_argv_args) / sizeof(char *);

/**
 *
 */
int main(int argc, char *argv[]) {

    int run_argc = 0;
    char *run_argv[argc + run_argc_args + 5];   // Make sure that we have enough room
    int i;
    
    for (i = 0; run_argv_args[i] != (char *) '\0'; i++) {
        run_argv[run_argc++] = run_argv_args[i];
    }

    static char *opt_env = "--setenv";
    static char *opt_grp = "--gid";
    int ch;
    uid_t uid = 0;
    uint32_t flags = F_AUTH_PROMPT;

    while ((ch = getopt_long(argc, argv, "+u:g:shnvS", argv_options, '\0')) != -1) {
        switch (ch) {
            case 'u':
                if (parseuid(optarg, &uid) == false) {
                    errx(1, "Invalid user");
                    
                } else if (strcmp(run_argv[run_argc_args - 3], "--uid") != 0
                      && strcmp(run_argv[run_argc_args - 2], "0") != 0) {
                      
                    /* This is an additional security check that makes sure 
                       that there is no mistakes in 'run_argc_args' */
                    errx(1, "Mismatch in argv");
                }

                run_argv[run_argc_args - 2] = optarg;
                
                break;
                
            case 'g':
                if (validategid(optarg) == false) {
                    errx(1, "Invalid group");
                }
                
                run_argv[run_argc++] = opt_grp;
                run_argv[run_argc++] = optarg;
                
                break;
                
            case 's':
                flags |= F_SHELL;
                break;
                
            case 'S':
                flags |= F_AUTH_STDIN;
                break;
                
            case 'n':
                flags &= ~F_AUTH_PROMPT;
                break;
                
            case 'h':
                usage();
                exit(0);
                
            case 'v':
                printf("runas %s\n", RUNAS_VERSION);
                exit(0);
                
            case 0:
                run_argv[run_argc++] = opt_env;
                run_argv[run_argc++] = optarg;
                break;
                
            default:
                usage();
                exit(1);
        }
    }
    
    argv += optind;
    argc -= optind;
    
    char **fixed_args;
    
    if ((flags & F_SHELL) != 0) {
        fixed_args = (char *[]) {"--shell", "--scope", '\0'};
        
        if (argc > 0) {
            errx(1, "Not expecting arguments with the --shell option");
            
        } else if ((flags & F_AUTH_STDIN) != 0) {
            errx(1, "The --stdin option is not allowed combined with the --shell option");
        }
        
    } else {
        fixed_args = (char *[]) {
            "--service-type=exec",
            "--wait",
            isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) && isatty(STDERR_FILENO) ? "--pty" : "--pipe", 
            "--",
            '\0'
        };
    }
    
    for (i = 0; fixed_args[i] != (char *) '\0'; i++) {
        run_argv[run_argc++] = fixed_args[i];
    }
    
    for (i = 0; i < argc; i++) {
        run_argv[run_argc++] = argv[i];
    }
    
    run_argv[run_argc] = '\0';
    
    if (authenticate(uid, flags) == AUTH_SUCCESS) {
        if (setuid(0) != 0) {
            errx(1, "Failed to set uid");
        }
        
        execvp(run_argv[0], run_argv);
        errx(1, "Failed to launch process");
    }
    
    errx(1, "Authentcation failed");
}

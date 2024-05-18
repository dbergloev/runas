#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

// Internal headers
#include "common.h"
#include "read_passwd.h"
#include "authenticate.h"

#ifndef RUNAS_PRIV_GROUP
#define RUNAS_PRIV_GROUP "wheel"
#endif

/**
 *
 */
static bool isgrp(const char *username, const char *groupname) {
    gid_t groups[NGROUPS_MAX];
    int num_groups = getgroups(NGROUPS_MAX, groups);
    
    if (num_groups < 1) {
        return false;
    }
    
    struct group *grp;
    for (int i = 0; i < num_groups; i++) {
        grp = getgrgid(groups[i]);
        
        if (grp && strcmp(grp->gr_name, groupname) == 0) {
            return true;
        }
    }
    
    return false;
}

/**
 *
 */
static bool getuname(const uid_t uid, char *buffer, const size_t buffer_size) {
    struct passwd *pw = getpwuid(uid);
    
    if (!pw) {
        return false;
    }
    
    size_t len = strlen(pw->pw_name);
    if (len >= buffer_size) {
        return false;
    }
    
    strcpy(buffer, pw->pw_name);
    
    return true;
}

/**
 * Compare passwords with constant time
 */
static int compare_pwd(const char *usr, const char *pwd) {
    int usr_len = strlen(usr);
    int pwd_len = strlen(pwd);
    int result = usr_len ^ pwd_len; // Immediate fail if length differ
    int i;
    
    char *usr_inv = malloc(usr_len + 1);
    if (!usr_inv) {
        return -1;
    } else {
        usr_inv[usr_len] = '\0';
    }
    
    /*
     * Inverse the user provided password so that it does not match against itself.
     * If DB password is shorter than the user provided one, 
     * we start matching against itself. This avoids timing attacks that could be able
     * to detect the correct password length. 
     * We always loop against the size of the user provided password and always to the end.
     */
    for (i = 0; i < usr_len; i++) {
        usr_inv[i] = (char) (~usr[i]);
    }
    
    /**
     * Compare the two passwords one character at a time. 
     * We don't stop, even if a mismatch is found. Password match
     * will always use time that equals the length of the user provided password.
     */
    for (i = 0; i < usr_len; i++) {
        result |= i >= pwd_len ? (usr[i] ^ usr_inv[i]) : (usr[i] ^ pwd[i]);
    }
    
    free(usr_inv);

    return result;  // Non-zero result indicates mismatch
}

/**
 *
 */
auth_t authenticate(const uid_t target, const uint32_t flags) {
    char passwd[MAX_PASSWORD_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char *groupname = RUNAS_PRIV_GROUP;
    uid_t uid = getuid();

    if (target == uid || uid == 0) {
        return AUTH_SUCCESS;
        
    } else if ((flags & F_AUTH_PROMPT) == 0 && (flags & F_AUTH_STDIN) == 0) {
        return AUTH_DENIED;
        
    } else if (getuname(uid, username, MAX_USERNAME_LENGTH) == false) {
        return AUTH_FAILED;
        
    } else if (isgrp(username, groupname) == false) {
        return AUTH_DENIED;
        
    } else if (read_passwd(passwd, MAX_PASSWORD_LENGTH, flags) == false) {
        return AUTH_FAILED;
    }
    
    struct spwd *pwd = getspnam(username);
    if (!pwd) {
        return AUTH_FAILED;
    }
    
    char *hash = crypt(passwd, pwd->sp_pwdp);
    auth_t auth_status = AUTH_SUCCESS;
    
    if (compare_pwd(hash, pwd->sp_pwdp) != 0) {
        auth_status = AUTH_DENIED;
    }
    
    // Zero out the password buffer
    bzero(passwd, strlen(passwd));
    
    return auth_status;
}


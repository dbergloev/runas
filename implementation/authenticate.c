#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#ifdef RUNAS_AUTH_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#else
#include <shadow.h>
#include <crypt.h>
#endif

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

#ifndef RUNAS_AUTH_PAM
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
#else
int pam_auth_conv(int msg_len, const struct pam_message **msg,
                struct pam_response **resp, void *flags) {
                
    struct pam_response *reply = '\0';
    char passwd[MAX_PASSWORD_LENGTH];
    
    for (int i = 0; i < msg_len; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                if (read_passwd(passwd, MAX_PASSWORD_LENGTH, *((uint32_t *) flags)) == false) {
                    return PAM_CONV_ERR;
                }
                
                reply = (struct pam_response *) malloc(sizeof(struct pam_response));
                if (!reply) {
                    return PAM_CONV_ERR;
                }
                
                reply->resp = strdup(passwd);
                reply->resp_retcode = 0;
                *resp = reply;
                
                // Zero out the password buffer
                bzero(passwd, strlen(passwd));
                
                break;
            
            case PAM_ERROR_MSG:
                fprintf(stdout, "%s\n", msg[i]->msg);
                break;
            
            case PAM_TEXT_INFO:
                fprintf(stderr, "%s\n", msg[i]->msg);
                break;
            
            default:
                if (*resp != (struct pam_response *) '\0') {
                    bzero(reply->resp, strlen(reply->resp));
                    free(reply->resp);
                    free(reply);
                }
                
                return PAM_CONV_ERR;
        }
    }
    
    return PAM_SUCCESS;
}
#endif

/**
 *
 */
auth_t authenticate(const uid_t target, const uint32_t flags) {
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
    }
    
#ifndef RUNAS_AUTH_PAM
    char passwd[MAX_PASSWORD_LENGTH];
    
    if (read_passwd(passwd, MAX_PASSWORD_LENGTH, flags) == false) {
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
#else
    pam_handle_t *pamh = '\0';
    int retval;
    
    struct pam_conv conv = {
        pam_auth_conv,
        (void *) &flags
    };
    
    // Start PAM authentication
    retval = pam_start("runas", username, &conv, &pamh);

    if (retval == PAM_SUCCESS) {
        // Authenticate the user
        retval = pam_authenticate(pamh, 0);
    }

    if (retval == PAM_SUCCESS) {
        // Check if the account is valid (not expired, etc.)
        retval = pam_acct_mgmt(pamh, 0);
    }

    // End PAM transaction
    pam_end(pamh, retval);

    if (retval != PAM_SUCCESS) {
        return AUTH_DENIED;
    }
    
    return AUTH_SUCCESS;
#endif
}


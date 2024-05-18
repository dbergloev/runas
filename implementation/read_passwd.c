#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

// Internal headers
#include "common.h"

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

/**
 *
 */
bool read_passwd(char *buffer, const int buffer_len, const uint32_t flags) {
    static char *prompt = "Enter password: ";
    struct termios old_settings, new_settings;
    int rc, i=0;
    int input, output;
    int flags_fcntl;
    char ch;
    
    if ((flags & F_AUTH_STDIN) != 0 || (input = output = open(_PATH_TTY, O_RDWR)) == -1) {
        input = STDIN_FILENO;
        output = STDERR_FILENO;
    }
    
    if ((flags & F_AUTH_STDIN) == 0) {
        // Disable ECHO mode
        tcgetattr(input, &old_settings);
        new_settings = old_settings;
        new_settings.c_lflag &= ~(ICANON | ECHO);

        if (tcsetattr(input, TCSANOW, &new_settings) != 0) {
            return false;
        }
        
        write(output, prompt, strlen(prompt));
        
    } else if ((flags_fcntl = fcntl(input, F_GETFL, 0)) == -1
                  || (fcntl(input, F_SETFL, flags_fcntl | O_NONBLOCK) == -1)) {
        
        return false;
    }
    
    errno = 0;
    while ((rc = read(input, &ch, 1)) == 1 && ch != '\r' && ch != '\n' && i < buffer_len - 1) {
        if (ch == 127 || ch == 8) { // handle backspace
            if (i != 0) {
                i--;
                write(output, "\b \b", 3);
            }
            
        } else {
            buffer[i++] = ch;
            
            if ((flags & F_AUTH_STDIN) == 0) {
                write(output, "*", 1);
            }
        }
    }
    
    buffer[i] = '\0';
    ch = '\0';
    
    if ((flags & F_AUTH_STDIN) == 0) {
        write(output, "\n", 1);
        
        // Reset ECHO mode back to default settings
        tcsetattr(input, TCSANOW, &old_settings);
        
    } else if (fcntl(input, F_SETFL, flags_fcntl) == -1
                  || (rc == -1 && errno != EAGAIN)) {
              
        return false;
    }
    
    return true;
}


#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

/**
 *
 */
bool read_passwd(char *buffer, const int buffer_len) {
    static char *prompt = "Enter password: ";
    struct termios old_settings, new_settings;
    int rc, input, output;
    int i = 0;
    char ch;
    
    if ((input = output = open(_PATH_TTY, O_RDWR)) == -1) {
        input = STDIN_FILENO;
        output = STDERR_FILENO;
    }

    // Disable ECHO mode
    tcgetattr(input, &old_settings);
    new_settings = old_settings;
    new_settings.c_lflag &= ~(ICANON | ECHO);

    if (tcsetattr(input, TCSANOW, &new_settings) != 0) {
        return false;
    }
    
    write(output, prompt, strlen(prompt));
    
    while ((rc = read(input, &ch, 1)) == 1 && ch != '\n' && i < buffer_len - 1) {
        if (ch == 127 || ch == 8) { // handle backspace
            if (i != 0) {
                i--;
                write(output, "\b \b", 3);
            }
            
        } else {
            buffer[i++] = ch;
            write(output, "*", 1);
        }
    }
    buffer[i] = '\0';
    write(output, "\n", 1);
    
    // Reset ECHO mode back to default settings
    tcsetattr(input, TCSANOW, &old_settings);
    
    return true;
}


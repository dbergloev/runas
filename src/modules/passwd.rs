// Copyright (c) 2024 Daniel Bergløv
// 
// Permission is hereby granted, free of charge, to any person obtaining a 
// copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.

/**
 * Terminal and password handling utilities for `runas`.
 *
 * This module provides two core features:
 * 
 *  1. **Constant-time string comparison** (`time_compare`) — used to safely
 *     compare user-supplied credentials against stored values without leaking
 *     timing information.
 *  2. **Secure password input** (`ask_password`) — prompts the user for a password
 *     through a terminal or standard input while disabling echo, restoring state
 *     afterward.
 */

use crate::shared::*;
use crate::errx;
use std::os::unix::io::RawFd;
use nix::sys::stat::Mode;
use zeroize::Zeroize;

use nix::libc::{
    STDIN_FILENO, 
    STDERR_FILENO
};

use nix::sys::termios::{
    SetArg, 
    LocalFlags, 
    Termios,
    tcsetattr, 
    tcgetattr
};
    
use nix::fcntl::{
    OFlag, 
    FcntlArg, 
    fcntl, 
    open
};
    
use nix::unistd::{
    read, 
    write
};

/**
 * Compare two strings in constant time.
 *
 * This function ensures consistent runtime regardless of input similarity
 * or mismatch position, mitigating timing side-channel attacks.
 *
 * - Compares byte-by-byte without early exit.
 * - Performs XOR over both byte arrays.
 * - Pads comparisons with inverted bytes if the second string is shorter,
 *   to avoid leaking password length through timing.
 *
 * The order of these arguments mater. Every operation is based on the 
 * known string. Any timing attempt will only ever time against the known
 * string, revealing nothing about the secret string. 
 *
 * Returns `true` if both strings are identical, `false` otherwise.
 */
pub fn time_compare(known: &str, secret: &str) -> bool {
    let     buff_known:  &[u8]   = known.as_bytes();
    let     buff_secret: &[u8]   = secret.as_bytes();
    let     known_len:   usize   = buff_known.len();
    let     secret_len:  usize   = buff_secret.len();
    let mut result:      usize   = known_len ^ secret_len; // Immediate fail if length differ
    let mut buff_inv:    Vec<u8> = vec![0u8; known_len];
    
    // Invert the 'known' password so that it does not match against itself.
    // If 'secret' password is shorter than the 'known' password, 
    // we start matching against itself. This avoids timing attacks that could be able
    // to detect the correct password length. 
    // We always loop against the 'known' password and always to the end.
    for i in 0..known_len {
        buff_inv[i] = !(buff_known[i]);
    }
    
    // Compare the two passwords one character at a time. 
    // We don't stop, even if a mismatch is found. Password match
    // will always use time that equals the length of the 'self' password.
    for i in 0..known_len {
        result |= if i >= secret_len {
            buff_known[i] ^ buff_inv[i]
        } else {
            buff_known[i] ^ buff_secret[i]
        } as usize
    }
    
    return result == 0;
}

/**
 * Prompt the user for a password securely.
 *
 * Displays a message on the terminal or reads from
 * standard input if `RunFlags::AUTH_STDIN` is set.
 *
 * - Disables terminal echo and canonical mode while reading input.
 * - Supports backspace and overwriting behavior.
 * - Restores terminal flags to their previous state on exit.
 * - Returns the collected password as a UTF-8 `String`.
 *
 * # Parameters
 * - `msg`: Prompt message displayed to the user.
 * - `flags`: Behavior control flags (`RunFlags::AUTH_STDIN`, etc.).
 *
 * # Returns
 * The password input as a `String`. On fatal I/O or UTF-8 conversion errors,
 * the process terminates via `errx!()`.
 */
pub fn ask_password(msg: &str, flags: RunFlags) -> String {
    let mut input:        RawFd   = STDIN_FILENO;
    let mut output:       RawFd   = STDERR_FILENO;
    let mut flags_fcntl:  i32     = 0;
    let mut ch:           [u8; 1] = [0; 1];
    let mut buffer:       Vec<u8> = Vec::new();
    let mut i:            usize   = 0;
    let mut term_flags            = LocalFlags::empty();
    
    // Configure the terminal/input
    if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
        if let Ok(fd) = open(PATH_TTY, OFlag::O_RDWR, Mode::empty()) {
            input = fd;
            output = fd;
        }
        
        if (flags & RunFlags::PROMPT_HIDE) != RunFlags::NONE {
            if let Ok(settings) = tcgetattr(input) {
                // Disable terminal ECHO mode
                let mut new_settings: Termios = settings.clone();
                
                term_flags = new_settings.local_flags;
                new_settings.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);

                tcsetattr(input, SetArg::TCSANOW, &new_settings).unwrap_or_else(|e| { errx!(1, "ask_password: {}\n\t{}", MSG_IO_TTY_ATTR, e); });
            
            } else {
                errx!(1, MSG_IO_TTY_ATTR);
            }
        }
        
        write(output, msg.as_bytes()).unwrap_or_else(|e| { errx!(1, "ask_password: {}\n\t{}", MSG_IO_TTY_ATTR, e); });

    } else if let Ok(flags) = fcntl(input, FcntlArg::F_GETFL) {
        flags_fcntl = flags;
    
        // Disable blocking mode when reading from input
        fcntl(input, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags_fcntl) | OFlag::O_NONBLOCK)).unwrap_or_else(|e| { errx!(1, "ask_password: {}\n\t{}", MSG_IO_NONBLOCK, e); });
    
    } else {
        errx!(1, MSG_IO_NONBLOCK);
    }
    
    // Begin reading the password into the buffer
    while let Ok(rc) = read(input, &mut ch) {
        if rc == 1 && ch[0] != b'\r' && ch[0] != b'\n' {
            if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE 
                    && (flags & RunFlags::PROMPT_HIDE) != RunFlags::NONE {
                    
                if ch[0] == 127 || ch[0] == 8 {
                    // Handle backspace
                    if i != 0 {
                        i -= 1;
                        write(output, b"\x08 \x08").ok();
                    }
                    
                    continue;
                
                } else {
                    buffer.insert(i, ch[0]);
                    write(output, b"*").ok();
                }
                
            } else {
                buffer.push(ch[0]);
            }
            
            i += 1;
        
        } else {
            break;
        }
    }
    
    // Reset the terminal/input
    if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE 
            && (flags & RunFlags::PROMPT_HIDE) != RunFlags::NONE {
    
        write(output, b"\n").ok();
        
        // Reset ECHO mode back to default settings
        if let Ok(settings) = tcgetattr(input) {
            let mut new_settings: Termios = settings.clone();
            
            /*
             * local_flags is not an integer types. It's an object that implements
             * bitwise operations against it's own type. This means that we cannot
             * assign a value directly, but we can inverse the old value, append it
             * using bitwise-and to reset it and then append the new (old) flags.
             */
            new_settings.local_flags &= !(new_settings.local_flags);
            new_settings.local_flags |= term_flags;

            tcsetattr(input, SetArg::TCSANOW, &new_settings).ok();
        }
        
    } else if (flags & RunFlags::AUTH_STDIN) != RunFlags::NONE {
        // Re-enable blocking mode in input
        fcntl(input, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags_fcntl))).ok();
    }
    
    let result = match std::str::from_utf8(&buffer[..i]) {
        Ok(s) => s.to_string(),
        Err(e) => {
            buffer.zeroize();
            ch[0] = b'\0';
            
            errx!(1, "ask_password: {}\n\t{}", MSG_PARSE_UTF8, e);
        }
    };
 
    if (flags & RunFlags::PROMPT_HIDE) != RunFlags::NONE {
        buffer.zeroize();
        ch[0] = b'\0';
    }
    
    result
}


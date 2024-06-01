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

use super::shared::*;
use nix::libc::{STDIN_FILENO, STDERR_FILENO};
use std::os::unix::io::RawFd;
use nix::fcntl::{OFlag, FcntlArg, fcntl, open};
use nix::sys::stat::Mode;
use nix::sys::termios::{SetArg, LocalFlags, tcsetattr, tcgetattr};
use nix::unistd::{read, write};

/**
 * Compare two strings in constant time.
 *
 * This method does not return on the first mismatch. 
 * It will perform the operation in constant time and it
 * will compare the strings byte for byte.
 */
pub fn time_compare(str1: &str, str2: &str) -> bool {
    let buff1 = str1.as_bytes();
    let buff2 = str2.as_bytes();
    let buff1_len = buff1.len();
    let buff2_len = buff2.len();
    let mut result = buff1_len ^ buff2_len; // Immediate fail if length differ
    let mut buff_inv = vec![0u8; buff1_len];
    
    // Inverse the 'str1' password so that it does not match against itself.
    // If 'str2' password is shorter than the 'str1' password, 
    // we start matching against itself. This avoids timing attacks that could be able
    // to detect the correct password length. 
    // We always loop against the 'str1' password and always to the end.
    for i in 0..buff1_len {
        buff_inv[i] = !(buff1[i]);
    }
    
    // Compare the two passwords one character at a time. 
    // We don't stop, even if a mismatch is found. Password match
    // will always use time that equals the length of the 'self' password.
    for i in 0..buff1_len {
        result |= if i >= buff2_len {
            buff1[i] ^ buff_inv[i]
        } else {
            buff1[i] ^ buff2[i]
        } as usize
    }
    
    return result == 0;
}

/**
 *
 */
pub fn ask_password(msg: &str, flags: RunFlags) -> String {
    let mut input: RawFd = STDIN_FILENO;
    let mut output: RawFd = STDERR_FILENO;
    let mut flags_fcntl = 0;
    let mut ch = [0; 1];
    let mut buffer: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    let mut term_flags: LocalFlags = LocalFlags::empty();
    
    // Configure the terminal/input
    if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
        if let Ok(fd) = open(PATH_TTY, OFlag::O_RDWR, Mode::empty()) {
            input = fd;
            output = fd;
        }
        
        if let Ok(settings) = tcgetattr(input) {
            // Disable terminal ECHO mode
            let mut new_settings = settings.clone();
            term_flags = new_settings.local_flags;
            new_settings.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);

            tcsetattr(input, SetArg::TCSANOW, &new_settings).unwrap_or_else(|e| { errx!(1, "ask_password: {}\n\t{}", MSG_IO_TTY_ATTR, e); });
        
        } else {
            errx!(1, MSG_IO_TTY_ATTR);
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
            if ch[0] == 127 || ch[0] == 8 {
                // Handle backspace
                if i != 0 {
                    i -= 1;
                    write(output, b"\x08 \x08").ok();
                }
            
            } else {
                buffer.insert(i, ch[0]);
                i += 1;

                if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
                    write(output, b"*").ok();
                }
            }
        
        } else {
            break;
        }
    }
    
    // Reset the terminal/input
    if (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
        write(output, b"\n").ok();
        
        // Reset ECHO mode back to default settings
        if let Ok(settings) = tcgetattr(input) {
            let mut new_settings = settings.clone();
            
            // We cannot assign directly, so reset the flags and then append the old ones
            new_settings.local_flags &= !(new_settings.local_flags);
            new_settings.local_flags |= term_flags;

            tcsetattr(input, SetArg::TCSANOW, &new_settings).ok();
        }
        
    } else {
        // Re-enable blocking mode in input
        fcntl(input, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags_fcntl))).ok();
    }
    
    return std::str::from_utf8(&buffer[..i])
            .unwrap_or_else(|e| { errx!(1, "ask_password: {}\n\t{}", MSG_PARSE_UTF8, e); })
            .to_string();
}


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

use bitflags::bitflags;

/* Just because Rust's naming scheme is ugly and stupid.
 * It may not be a real NULL pointer, but it symbols the same thing. 
 */
pub type NULL = ();
pub const NULL: NULL = ();

pub const MSG_CALL_IMPL: &'static str = "Invalid call to missing implementation";
pub const MSG_PARSE_UTF8: &'static str = "Failed to parse UTF-8 data";
pub const MSG_PARSE_CSTRING: &'static str = "Failed to parse CString";
pub const MSG_PARSE_NUM: &'static str = "Failed to parse numeric value";
pub const MSG_IO_USER_DB: &'static str = "Failed to open user database";
pub const MSG_IO_TTY_ATTR: &'static str = "Failed to configure TTY for user input";
pub const MSG_IO_NONBLOCK: &'static str = "Failed to set input stream to non-blocking mode";
pub const MSG_PAM_NULL_POINTER: &'static str = "Failed PAM authentication, received null pointer message";

pub const AUTH_GROUP: &'static str = "wheel";
pub const EMPTY: &'static str = "";
pub const PATH_TTY: &'static str = "/dev/tty";
pub const PROMPT_TEXT: &'static str = "Password: ";

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RunFlags: u32 {
        const NONE = 0x00;
        const SHELL = 0x01;
        const AUTH_STDIN = 0x20;
        const AUTH_NO_PROMPT = 0x40;
    }
}

#[macro_export]
macro_rules! errx {
    ($x:expr) => {
        std::process::exit($x);
    };
    
    ($x:expr, $y:expr) => {
        eprintln!("{}", $y);
        std::process::exit($x);
    };

    ($x:expr, $y:expr, $($z:expr),+) => {
        eprintln!($y, $($z),+);
        std::process::exit($x);
    };
}


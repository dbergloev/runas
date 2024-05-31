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

mod c_ffi {
    extern crate libc;

    use libc::{spwd, c_char};

    extern "C" {
        /**
         * Link to the crypt() function in libcrypt C library.
         * Requires '-l crypt' build option.
         */
        pub fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
        
        /**
         * Link to libc getspnam() function.
         */
        pub fn getspnam(name: *const c_char) -> *mut spwd;
    }
}

use super::shared::*;
use std::ffi::{CStr, CString};
use std::ptr;

/**
 * A Rust implemented version of libcrypt::crypt C function
 */
pub fn crypt(passwd: &str, salt: &str) -> Option<String> {
    let c_passwd = CString::new(passwd).unwrap_or_else(|e| { errx!(1, "crypt: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    let c_salt = CString::new(salt).unwrap_or_else(|e| { errx!(1, "crypt: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    
    unsafe {
        let result = c_ffi::crypt(c_passwd.as_ptr(), c_salt.as_ptr());
        
        if result != ptr::null_mut() {
            return Some(CStr::from_ptr(result).to_string_lossy().into_owned());   
        }
    }
    
    return None;
}

/**
 * A Rust implemented version of libc::getspnam C function
 */
pub fn getspnam(username: &str) -> Option<String> {
    let c_username = CString::new(username).unwrap_or_else(|e| { errx!(1, "getspnam: {}\n\t{}", MSG_PARSE_CSTRING, e); });

    unsafe {
        let spwd_ptr = c_ffi::getspnam(c_username.as_ptr());
        
        if spwd_ptr != ptr::null_mut() {
            let spwd_ref = &*spwd_ptr;
            let password_hash = CStr::from_ptr(spwd_ref.sp_pwdp).to_string_lossy().into_owned();
            
            return Some(password_hash);
        }
    }
    
    return None;
}


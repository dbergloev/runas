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
use std::ffi::{CString, CStr};
use std::{mem, ptr};
use libc::{c_int, c_void, size_t, free, calloc, strdup};

mod c_ffi {    
    #[allow(dead_code)]
    pub const PAM_PROMPT_ECHO_OFF: i32 = 1;
    #[allow(dead_code)]
    pub const PAM_PROMPT_ECHO_ON: i32 = 2;
    #[allow(dead_code)]
    pub const PAM_ERROR_MSG: i32 = 3;
    #[allow(dead_code)]
    pub const PAM_TEXT_INFO: i32 = 4;
    
    use libc::{c_int, c_char, c_void};
    
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_message {
        pub msg_style: c_int,
        pub msg: *const c_char,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_response {
        pub resp: *mut c_char,
        pub resp_retcode: c_int,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_conv {
        pub conv: unsafe extern "C" fn(
            num_msg: c_int,
            msg: *const *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut c_void,
        ) -> c_int,
        pub appdata_ptr: *mut c_void,
    }

    extern "C" {
        pub fn pam_start(service_name: *const c_char, user: *const c_char, 
                            pam_conversation: *const pam_conv, pamh: *mut *mut super::pam_handle_t) -> c_int;
                            
        pub fn pam_authenticate(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_acct_mgmt(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_end(pamh: *mut super::pam_handle_t, pam_status: c_int) -> c_int;
    }
}

#[allow(non_camel_case_types)]
pub type pam_handle_t = u8;

#[allow(dead_code)]
pub const PAM_SUCCESS: i32 = 0;
#[allow(dead_code)]
pub const PAM_SYSTEM_ERR: i32 = 4;
#[allow(dead_code)]
pub const PAM_BUF_ERR: i32 = 5;
#[allow(dead_code)]
pub const PAM_PERM_DENIED: i32 = 6;
#[allow(dead_code)]
pub const PAM_AUTH_ERR: i32 = 7;
#[allow(dead_code)]
pub const PAM_CRED_INSUFFICIENT: i32 = 8;
#[allow(dead_code)]
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
#[allow(dead_code)]
pub const PAM_USER_UNKNOWN: i32 = 10;
#[allow(dead_code)]
pub const PAM_MAXTRIES: i32 = 11;
#[allow(dead_code)]
pub const PAM_NEW_AUTHTOK_REQD: i32 = 12;
#[allow(dead_code)]
pub const PAM_ACCT_EXPIRED: i32 = 13;
#[allow(dead_code)]
pub const PAM_CONV_ERR: i32 = 19;
#[allow(dead_code)]
pub const PAM_ABORT: i32 = 26;

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
/**
 * Defines the message types from PAM.
 */
pub enum CONV {
    ECHO_ON,
    ECHO_OFF,
    MSG,
    ERROR
}

/**
 * A PAM conversation implementation to be used with `pam_start()`.
 */
pub trait PamConv {
    fn prompt(&mut self, msg: &str, style: CONV) -> Result<String, NULL>;
    fn msg(&mut self, msg: &str, style: CONV);
}

/**
 * Wrapper for PAM conversations. 
 *
 * This function sits between PAM and `PamConv`.
 * It allows `PamConv` to be fully Rust without the need for 
 * `CString`, `unsafe {}` blocks and so on. 
 */
unsafe extern "C" fn pam_conv_wrap<T: PamConv>(
        num_msg: c_int, 
        msg: *const *const c_ffi::pam_message, 
        resp: *mut *mut c_ffi::pam_response, 
        appdata_ptr: *mut c_void) -> c_int {
    
    let reply = calloc(num_msg as size_t, mem::size_of::<c_ffi::pam_response>() as size_t) as *mut c_ffi::pam_response;
    let mut result = PAM_SUCCESS;

    if reply.is_null() {
        return PAM_BUF_ERR as c_int;
    }

    let callback = &mut *(appdata_ptr as *mut T);

    for i in 0..num_msg {
        let reqest_ptr = *(msg.offset(i as isize)) as *const c_ffi::pam_message;
        let reply_ptr = reply.offset(i as isize) as *mut c_ffi::pam_response;
        
        if reqest_ptr == ptr::null() || reply_ptr == ptr::null_mut() {
            errx!(1, "pam_conv: {}", MSG_PAM_NULL_POINTER);
        }
        
        let reqest = &(*reqest_ptr);
        let reply = &mut *reply_ptr;
        
        let msg = if reqest.msg == ptr::null() {
            EMPTY
            
        } else {
            CStr::from_ptr(reqest.msg).to_str().unwrap_or_else(|e| { errx!(1, "pam_conv: {}\n\t{}", MSG_PARSE_CSTRING, e); })
        };
        
        match reqest.msg_style as i32 {
            c_ffi::PAM_PROMPT_ECHO_ON |
            c_ffi::PAM_PROMPT_ECHO_OFF => {
            
                let style = if reqest.msg_style as i32 == c_ffi::PAM_PROMPT_ECHO_ON {
                    CONV::ECHO_ON
                } else {
                    CONV::ECHO_OFF
                };
            
                if let Ok(ret) = callback.prompt(msg, style) {
                    let ret = CString::new(&*ret).unwrap_or_else(|e| { errx!(1, "pam_conv: {}\n\t{}", MSG_PARSE_CSTRING, e); });
                    reply.resp = strdup(ret.as_ptr());
                    
                } else {
                    result = PAM_CONV_ERR;
                }
            }
            
            c_ffi::PAM_ERROR_MSG => {
                callback.msg(msg, CONV::ERROR);
            }
            
            c_ffi::PAM_TEXT_INFO => {
                callback.msg(msg, CONV::MSG);
            }
            
            _ => result = PAM_CONV_ERR
        }
        
        if result != PAM_SUCCESS {
            break;
        }
    }
    
    if result != PAM_SUCCESS {
        free(reply as *mut c_void);
    
    } else {
        *resp = reply;
    }
    
    return result as c_int;
}

/**
 * 
 */
pub fn pam_start<'a, T: PamConv>(service: &str, username: &str, conversation: &mut T) -> Result<&'a mut pam_handle_t, i32> where {
    let mut handle: *mut pam_handle_t = std::ptr::null_mut();
    let c_service = CString::new(service).unwrap_or_else(|e| { errx!(1, "pam_start: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    let c_username = CString::new(username).unwrap_or_else(|e| { errx!(1, "pam_start: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    let result: i32;
    
    let mut conversation = c_ffi::pam_conv {
        conv: pam_conv_wrap::<T>,
        appdata_ptr: conversation as *mut T as *mut c_void
    };
    
    unsafe {
        result = c_ffi::pam_start(c_service.as_ptr(), c_username.as_ptr(), &mut conversation, &mut handle) as i32;
    }
        
    if result == PAM_SUCCESS && !handle.is_null() {
        return Ok(unsafe { &mut *handle });
    }
    
    Err(result)
}

/**
 * 
 */
pub fn pam_authenticate(handle: &mut pam_handle_t, flags: u32) -> Result<NULL, i32> {
    let result: i32;
    
    unsafe {
        result = c_ffi::pam_authenticate(handle, flags as c_int) as i32;
    }
    
    if result == PAM_SUCCESS {
        return Ok(NULL);
    }
    
    Err(result)
}

/**
 * 
 */
pub fn pam_acct_mgmt(handle: &mut pam_handle_t, flags: u32) -> Result<NULL, i32> {
    let result: i32;
    
    unsafe {
        result = c_ffi::pam_acct_mgmt(handle, flags as c_int) as i32;
    }
    
    if result == PAM_SUCCESS {
        return Ok(NULL);
    }
    
    Err(result)
}

/**
 * 
 */
pub fn pam_end(handle: &mut pam_handle_t, status: i32) -> Result<NULL, i32> {
    let result: i32;
    
    unsafe {
        result = c_ffi::pam_end(handle, status as c_int) as i32;
    }
    
    if result == PAM_SUCCESS {
        return Ok(NULL);
    }
    
    Err(result)
}


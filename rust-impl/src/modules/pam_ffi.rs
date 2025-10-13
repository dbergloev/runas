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
 * PAM (Pluggable Authentication Module) bindings and wrappers for `runas`.
 *
 * This module implements minimal and memory-safe Rust bindings around
 * the PAM (Pluggable Authentication Module) C API. 
 * It allows `runas` to perform password-based authentication and account validation
 * using system PAM policies, without directly linking against or maintaining its own
 * C glue code elsewhere.
 *
 * All `unsafe` FFI operations are fully encapsulated inside this file.
 * The public interface is designed to be safe for external use, provided
 * it is used as intended. Rust’s safety guarantees cannot extend into the
 * C library, but every call is validated and checked at the boundary.
 */

use super::shared::*;
use std::cell::Cell;

use std::ffi::{
    CString, 
    CStr
};
    
use std::{
    mem, 
    ptr
};
    
use libc::{
    c_int, 
    c_void, 
    size_t, 
    free, 
    calloc, 
    strdup
};

// -------------------------
// Raw C FFI declarations
// -------------------------
// The `c_ffi` module exposes unmodified libc-compatible bindings for libpam.
// These are kept private to isolate `unsafe` usage and reduce public API surface.

mod c_ffi {    

    use libc::{
        c_int, 
        c_char, 
        c_void
    };

    #[allow(dead_code)]
    pub const PAM_PROMPT_ECHO_OFF: i32 = 1;
    #[allow(dead_code)]
    pub const PAM_PROMPT_ECHO_ON: i32 = 2;
    #[allow(dead_code)]
    pub const PAM_ERROR_MSG: i32 = 3;
    #[allow(dead_code)]
    pub const PAM_TEXT_INFO: i32 = 4;
    
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_message {
        pub msg_style: c_int,
        pub msg:       *const c_char,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_response {
        pub resp:         *mut c_char,
        pub resp_retcode: c_int,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_conv {
        pub conv: unsafe extern "C" fn(
            num_msg:     c_int,
            msg:         *const *const pam_message,
            resp:        *mut *mut pam_response,
            appdata_ptr: *mut c_void,
        ) -> c_int,
        pub appdata_ptr: *mut c_void,
    }

    unsafe extern "C" {
        pub fn pam_start(service_name: *const c_char, user: *const c_char, 
                            pam_conversation: *const pam_conv, pamh: *mut *mut super::pam_handle_t) -> c_int;
                            
        pub fn pam_authenticate(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_acct_mgmt(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_end(pamh: *mut super::pam_handle_t, pam_status: c_int) -> c_int;
        pub fn pam_getenvlist(pamh: *mut super::pam_handle_t) -> *mut *mut libc::c_char;
        pub fn pam_setcred(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_open_session(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_close_session(pamh: *mut super::pam_handle_t, flags: c_int) -> c_int;
        pub fn pam_set_item(pamh: *mut super::pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
    }
}

#[allow(non_camel_case_types)]
pub type pam_handle_t = u8;

/*
 * Error codes from PAM
 */
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

/*
 * PAM item types
 */
pub const PAM_TTY: i32          = 3;
#[allow(dead_code)]
pub const PAM_USER: i32         = 2;
#[allow(dead_code)]
pub const PAM_RUSER: i32        = 8;

/*
 * Used by pam_setcred()
 */
#[allow(dead_code)]
pub const PAM_ESTABLISH_CRED: i32   = 0x0002;
#[allow(dead_code)]
pub const PAM_DELETE_CRED: i32      = 0x0004;

/**
 * Defines the message types emitted during PAM conversation callbacks.
 */
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum CONV {
    ECHO_ON,
    ECHO_OFF,
    MSG,
    ERROR
}

/**
 * High-level conversation interface for PAM authentication.
 *
 * Implementations of this trait receive messages and prompts
 * during authentication and respond accordingly.
 */
pub trait PamConv {
    fn prompt(&mut self, msg: &str, style: CONV) -> Result<String, NULL>;
    fn msg(&mut self, msg: &str, style: CONV);
}

// -------------------------
// Conversation bridge
// -------------------------

/**
 * FFI-compatible callback adapter between PAM and a Rust `PamConv` object.
 *
 * Called internally by PAM through the `pam_conv` structure.
 * Performs string decoding, allocates a response array, and invokes the
 * user-defined callback. Errors are mapped to PAM_CONV_ERR.
 */
unsafe extern "C" fn pam_conv_wrap<T: PamConv>(
        num_msg: c_int, 
        msg: *const *const c_ffi::pam_message, 
        resp: *mut *mut c_ffi::pam_response, 
        appdata_ptr: *mut c_void) -> c_int {
    
    let mut result = PAM_SUCCESS;
    let reply = unsafe {
        calloc(num_msg as size_t, mem::size_of::<c_ffi::pam_response>() as size_t) as *mut c_ffi::pam_response
    };

    if reply.is_null() {
        return PAM_BUF_ERR as c_int;
    }

    let callback = unsafe {
        &mut *(appdata_ptr as *mut T)
    };

    for i in 0..num_msg {
        let reqest_ptr = unsafe { 
            *(msg.offset(i as isize)) as *const c_ffi::pam_message 
        };
        
        let reply_ptr = unsafe { 
            reply.offset(i as isize) as *mut c_ffi::pam_response 
        };
        
        if reqest_ptr == ptr::null() || reply_ptr == ptr::null_mut() {
            errx!(1, "pam_conv: {}", MSG_PAM_NULL_POINTER);
        }
        
        let reqest = unsafe {
            &(*reqest_ptr)
        };
        
        let reply = unsafe {
            &mut *reply_ptr
        };
        
        let msg = if reqest.msg == ptr::null() {
            EMPTY
            
        } else {
            unsafe {
                CStr::from_ptr(reqest.msg).to_str().unwrap_or_else(|e| { errx!(1, "pam_conv: {}\n\t{}", MSG_PARSE_CSTRING, e); })
            }
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
                    reply.resp = unsafe {
                        strdup(ret.as_ptr())
                    };
                    
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
        unsafe {
            free(reply as *mut c_void);
        }
    
    } else {
        unsafe {
            *resp = reply;
        }
    }
    
    return result as c_int;
}

// -------------------------
// Wrapper functions
// -------------------------

/**
 *
 */
pub struct PamHandle {
    handle: *mut pam_handle_t,
    result: Cell<i32>,
    session: Cell<bool>
}

/**
 *
 */
impl PamHandle {
    /**
     * Authenticate a user associated with the given PAM handle.
     */
    pub fn authenticate(&self, flags: u32) -> i32 {
        unsafe {
            self.result.set(c_ffi::pam_authenticate(self.handle, flags as c_int) as i32);
        }
        
        self.result.get()
    }

    /**
     * Perform PAM account management checks (e.g., expiration, validity).
     */
    pub fn acct_mgmt(&self, flags: u32) -> i32 {
        unsafe {
            self.result.set(c_ffi::pam_acct_mgmt(self.handle, flags as c_int) as i32);
        }
        
        self.result.get()
    }

    /**
     * Open a new PAM session for the authenticated user.
     *
     * This should be called after successful authentication and account checks.
     * It initializes session modules like pam_systemd, pam_env, etc.
     */
    pub fn open_session(&self, flags: u32) -> i32 {
        if self.session.get() {
            return PAM_SUCCESS;
        }
    
        unsafe { 
            let mut result = c_ffi::pam_setcred(self.handle, PAM_ESTABLISH_CRED as c_int) as i32;
            
            if result == PAM_SUCCESS {
                result = c_ffi::pam_open_session(self.handle, flags as c_int) as i32;
                
                if result != PAM_SUCCESS {
                    c_ffi::pam_setcred(self.handle, PAM_DELETE_CRED as c_int);
                }
            }
            
            self.result.set(result);
        }
        
        if self.result.get() == PAM_SUCCESS {
            self.session.set(true);
        }
        
        self.result.get()
    }

    /**
     * Close a previously opened PAM session.
     *
     * This should be called once the session process terminates.
     */
    pub fn close_session(&self, flags: u32) -> i32 {
        if !self.session.get() {
            return PAM_SUCCESS;
        }
    
        unsafe {
            let result = c_ffi::pam_close_session(self.handle, flags as c_int) as i32;
            
            if result == PAM_SUCCESS {
                c_ffi::pam_setcred(self.handle, PAM_DELETE_CRED as c_int);
            }
            
            self.result.set(result);
        }
        
        if self.result.get() == PAM_SUCCESS {
            self.session.set(false);
        }
        
        self.result.get()
    }
    
    /**
     * 
     */
    pub fn set_item(&self, item_type: i32, value: &str) -> i32 {
        let c_value = CString::new(value).unwrap_or_else(|e| { errx!(1, "set_item: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    
        unsafe {
            self.result.set(c_ffi::pam_set_item(self.handle, item_type as c_int, c_value.as_ptr() as *const c_void) as i32);
        }
        
        self.result.get()
    }
    
    /**
     * Get a list of environment variables from PAM.
     */
    pub fn getenvlist(&self) -> Vec<CString> {
        let mut envs = Vec::new();

        unsafe {
            let list = c_ffi::pam_getenvlist(self.handle);

            if list.is_null() {
                return envs;
            }
            
            /*
             * Self note for the future.
             * *p.add(i) = *(p + i) in C
             *
             * One of the most stupid naming conventions ever seen, 
             * in the history of programming, but that is typical Rust. 
             */

            let mut i = 0;
            loop {
                let entry = *list.add(i);
                if entry.is_null() {
                    break;
                }

                let c_str = CStr::from_ptr(entry);
                envs.push(CString::new(c_str.to_bytes()).unwrap());
                i += 1;
            }

            // Free each string and the list itself
            let mut j = 0;
            while !(*list.add(j)).is_null() {
                libc::free(*list.add(j) as *mut libc::c_void);
                j += 1;
            }
            libc::free(list as *mut libc::c_void);
        }

        envs
    }
}

/**
 *
 */
impl Drop for PamHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            if self.session.get() {
                self.close_session(0);
            }
        
            unsafe { 
                c_ffi::pam_end(self.handle, self.result.get() as c_int);
            }
            
            self.handle = std::ptr::null_mut();
        }
    }
}

/**
 * Initialize a PAM session and return a handle on success.
 *
 * @param service       PAM service name (e.g., "login", "sudo", "runas").
 * @param username      The target username to authenticate.
 * @param conversation  The conversation handler implementing `PamConv`.
 *
 * @return PAM handle wrapped in `Result`, or error code on failure.
 */
pub fn pam_start<T: PamConv>(service: &str, username: &str, conversation: &mut T) -> Result<PamHandle, i32> {
    let mut handle: *mut pam_handle_t = std::ptr::null_mut();
    let     c_service                 = CString::new(service).unwrap_or_else(|e| { errx!(1, "pam_start: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    let     c_username                = CString::new(username).unwrap_or_else(|e| { errx!(1, "pam_start: {}\n\t{}", MSG_PARSE_CSTRING, e); });
    let     result: i32;
    
    let mut conversation = c_ffi::pam_conv {
        conv: pam_conv_wrap::<T>,
        appdata_ptr: conversation as *mut T as *mut c_void
    };
    
    unsafe {
        result = c_ffi::pam_start(c_service.as_ptr(), c_username.as_ptr(), &mut conversation, &mut handle) as i32;
    }
        
    if result == PAM_SUCCESS && !handle.is_null() {
        return Ok(
            PamHandle {
                handle: handle,
                result: Cell::new(PAM_SUCCESS),
                session: Cell::new(false)
            }
        );
    }
    
    Err(result)
}


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
 * Unified authentication interface for `runas`.
 *
 * This module provides a single authentication entry point that selects between
 * two backends:
 *
 *  - **PAM-based authentication** (`--features use_pam`):  
 *    Uses the system’s Pluggable Authentication Module (PAM) stack to verify
 *    credentials and perform account management checks.
 *
 *  - **Shadow-file authentication** (default, no PAM):  
 *    Directly reads `/etc/shadow`, retrieves the stored password hash via
 *    `getspnam()`, and verifies it using `crypt()`.
 *
 * The top-level `authenticate()` function is responsible for determining whether
 * authentication is required, selecting the appropriate backend, and enforcing
 * privilege and membership checks.
 */

use cfg_if::cfg_if;

use super::shared::*;
use super::user::{
    Account,
    Group
};

cfg_if! {
    if #[cfg(not(feature = "use_pam"))] {
        pub type AuthType = bool;
        const DEFAULT_TRUE: AuthType = true;
        const DEFAULT_FALSE: AuthType = false;
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { *self }
        }
        
    } else if #[cfg(feature = "backend_scopex")] {
        use crate::ffi::pam::PAM_CRED_INSUFFICIENT;
        use std::env;
        
        pub type AuthType = Result<Vec<String>, u32>;
        #[allow(dead_code)]
        const DEFAULT_TRUE: AuthType = Ok(Vec::new());
        const DEFAULT_FALSE: AuthType = Err(PAM_CRED_INSUFFICIENT);
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { self.is_ok() }
        }
        
    } else {
        use crate::ffi::pam::{
            PAM_SUCCESS,
            PAM_AUTH_ERR
        };
        
        pub type AuthType = u32;
        const DEFAULT_TRUE: AuthType = PAM_SUCCESS;
        const DEFAULT_FALSE: AuthType = PAM_AUTH_ERR;
        
        impl TypeCheck for AuthType {
            #[inline]
            fn is_true(&self) -> bool { *self == PAM_SUCCESS }
        }
    }
}

/*
 * We use a sub module in order to wrap the feature check in a block.
 * Rust will not allow empty blocks for some stupid reason.
 */

#[cfg(feature = "use_pam")]
mod feat {

    use crate::modules::shared::*;
    use crate::modules::passwd::ask_password;
    use crate::modules::user::Account;
    use super::AuthType;
    
    use crate::ffi::pam::{
        CONV,
        PamConv, 
        pam_start
    };
    
    use crate::ffi::pam::{
        PAM_SUCCESS,
    };
    
    cfg_if! {
        if #[cfg(feature = "backend_scopex")] {
            use crate::modules::proc::watch_process;
            use std::borrow::Cow;
            use std::os::unix::io::AsRawFd;
            use std::process;
            use std::mem::drop;
            
            use crate::ffi::pam::{
                PAM_TTY,
                PAM_USER,
                PAM_RUSER
            };
            
            use nix::unistd::{
                isatty, 
                ttyname,
                fork,
                ForkResult
            };
        }
    }

    /**
     *
     */
    struct Conv {
        flags: RunFlags
    }
    
    impl PamConv for Conv {
        /**
         *
         */
        fn prompt(&mut self, msg: &str, _style: CONV) -> Result<String, NULL> {
            Ok(
                ask_password(msg, self.flags)
            )
        }
        
        /**
         *
         */
        fn msg(&mut self, msg: &str, style: CONV) {
            if style == CONV::MSG {
                println!("PAM info: {}", msg);
            
            } else {
                eprintln!("PAM error: {}", msg);
            }
        }
    }
    
    /**
     * PAM-based authentication backend.
     *
     * Uses the system PAM stack to authenticate a user interactively
     * through a conversation handler.
     */
    pub fn auth(
            user: &Account, 
            #[cfg(feature = "backend_scopex")] target: &Account, 
            flags: RunFlags,
            #[cfg(feature = "backend_scopex")] disable_auth: bool
    ) -> AuthType {
    
        let mut conv = Conv {flags};
        let mut pam_user = user.name();
        
        #[cfg(feature = "backend_scopex")]
        if disable_auth {
            pam_user = target.name();
        }
        
        match pam_start(env!("CARGO_PKG_NAME"), pam_user, &mut conv) {
            Ok(handle) => {
                cfg_if! {
                    if #[cfg(feature = "backend_scopex")] {
                        let mut result = PAM_SUCCESS;
                        let fd: i32 = std::io::stdin().as_raw_fd();
                        
                        if !disable_auth {
                            result = handle.authenticate(0);
                        }
                        
                        if let Ok(status) = isatty(fd) && status {
                            if let Ok(tty_path) = ttyname(fd) {
                                let tty_os: Cow<'_, str> = tty_path.as_os_str().to_string_lossy();
                                let tty: &str = tty_os.strip_prefix("/dev/").unwrap_or(&tty_os);
                               
                                result = handle.set_item(PAM_TTY, tty);
                            }
                        }
                        
                        if result == PAM_SUCCESS {
                            result = handle.set_item(PAM_RUSER, user.name());
                        }
                        
                        if !disable_auth {
                            if result == PAM_SUCCESS {
                                result = handle.acct_mgmt(0);
                            }
                            
                            if result == PAM_SUCCESS {
                                result = handle.set_item(PAM_USER, target.name());
                            }
                        }
                        
                        if result == PAM_SUCCESS {
                            result = handle.open_session(0);
                        }
                    
                        if result == PAM_SUCCESS {
                            match unsafe { fork() } {
                                Ok(ForkResult::Child) => {
                                    // Child process, return and continue
                                    return Ok(
                                        handle.getenvlist()
                                    )
                                }
                                
                                Ok(ForkResult::Parent { child }) => {
                                    // Wait for the process and keep PAM session alive
                                    let status_code: i32 = watch_process(child);
                                    
                                    // Ensure that PAM has a chance to quit before terminating
                                    drop(handle);
                                    
                                    // Terminate the parent when the child exits
                                    process::exit(status_code);
                                }
                                
                                Err(err) => {
                                    eprintln!("fork failed: {}", err);
                                }
                            }
                        }
                        
                        Err(result)
                    
                    } else {
                        let mut result = handle.authenticate(0);
                        
                        if result == PAM_SUCCESS {
                            result = handle.acct_mgmt(0);
                        }
                    
                        result
                    }
                }
            }
            
            Err(code) => {
                cfg_if! {
                    if #[cfg(feature = "backend_scopex")] {
                        Err(code)
                    
                    } else {
                        code
                    }
                }
            }
        }
    }
}

/**
 *
 */
#[cfg(not(feature = "use_pam"))]
mod feat {

    use crate::modules::shared::*;
    use crate::modules::user::Account;
    
    use crate::modules::passwd::{
        ask_password, 
        time_compare
    };
    
    use crate::ffi::shadow::{
        crypt, 
        getspnam
    };

    /**
     * Shadow-file authentication backend.
     */
    pub fn auth(user: &Account, flags: RunFlags) -> bool {
        if let Some(hash) = getspnam(user.name()) {
            let pwd = ask_password(PROMPT_TEXT, flags);
            
            if let Some(user_hash) = crypt(pwd, &hash) {
                return time_compare(&user_hash, &hash);
            }
            
        } else {
            errx!(1, "auth: {}", MSG_IO_USER_DB);
        }
    
        false
    }
}

/**
 *
 */
#[cfg(all(feature = "backend_scopex", feature = "use_pam"))]
pub fn get_envp() -> Vec<String> {
    env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

/**
 * Authenticate a user against a target account.
 *
 * @param user     The invoking account
 * @param target   The target account being accessed
 * @param flags    Runtime authentication flags
 *
 * @return `true` if authentication succeeds or is not required, `false` otherwise.
 */
pub fn authenticate(user: &Account, target: &Account, flags: RunFlags) -> AuthType {
    /*
     * The following will evaluate to true:
     *  - The user is root (Can do whatever they want).
     *  - The user is launching this as it's own UID and primary GID.
     *  - The user is launching this as it's own UID and a GID that the UID is a member of.
     *
     * The following will require authentication:
     *  - The user tries to switch UID away from it's own.              E.g. --uid
     *  - The user tries to access a GID that it is not a member of.    E.g. --gid
     */
    if user.is_root() || (target.uid() == user.uid()
                        && (target.gid() == user.gid() || user.is_member(target.group()))) {
                         
        cfg_if! {
            if #[cfg(all(feature = "backend_scopex", feature = "use_pam"))] {
                if target.uid() != user.uid() {
                    // Even when root, we should get a new session when switching user, but no authentication.
                    return feat::auth(user, target, flags, user.is_root());
                }
            
                return Ok( get_envp() );
            
            } else {
                return DEFAULT_TRUE;
            }
        }
        
    } else if (flags & RunFlags::AUTH_NO_PROMPT) != RunFlags::NONE 
            && (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
            
        /*
         * Password prompt was requested disabled while 
         * not requesting passing via stdin. 
         *
         * We just fail, beause auth() will launch a prompt if stdin is disabled, 
         * and caller did not want a prompt. 
         */
        return DEFAULT_FALSE;
        
    } else if let Some(wheel) = Group::from(AUTH_GROUP) {
        /*
         * We only allow the wheel group to reach outside their
         * own UID and GID's. 
         */
        if !user.is_member(&wheel) {
            return DEFAULT_FALSE;
        }
            
        cfg_if! {
            if #[cfg(all(feature = "backend_scopex", feature = "use_pam"))] {
                return feat::auth(user, target, flags, false);
                
            } else {
                return feat::auth(user, flags);
            }
        }
    }
    
    /*
     * Default to false.
     */
    DEFAULT_FALSE
}


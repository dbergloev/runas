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

use super::shared::*;
use super::user::Account;

/*
 * We use a sub module in order to wrap the feature check in a block.
 * Rust will not allow empty blocks for some stupid reason.
 */

#[cfg(feature = "use_pam")]
mod feat {

    use crate::modules::shared::*;
    use crate::modules::passwd::ask_password;
    use crate::modules::user::Account;
    use crate::modules::pam_ffi::{CONV, PAM_SUCCESS, PamConv, pam_start, pam_authenticate, pam_acct_mgmt, pam_end};

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
        fn prompt(& mut self, msg: &str, _style: CONV) -> Result<String, NULL> {
            Ok(ask_password(msg, self.flags))
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
    pub fn auth(user: &Account, flags: RunFlags) -> bool {
        let mut conv = Conv {flags};
        
        if let Ok(mut handle) = pam_start(env!("CARGO_PKG_NAME"), user.name(), &mut conv) {
            let mut result = match pam_authenticate(&mut handle, 0) {
                Ok(_) => 0 as i32,
                Err(code) => code
            };

            if result == PAM_SUCCESS {
                result = match pam_acct_mgmt(&mut handle, 0) {
                    Ok(_) => 0 as i32,
                    Err(code) => code
                };
            }
            
            pam_end(&mut handle, result).ok();
            
            if result == PAM_SUCCESS {
                return true;
            }
        }
    
        false
    }
}

#[cfg(not(feature = "use_pam"))]
mod feat {

    use crate::modules::shared::*;
    use crate::modules::passwd::{ask_password, time_compare};
    use crate::modules::user::Account;
    use crate::modules::shadow_ffi::{crypt, getspnam};

    /**
     * Shadow-file authentication backend.
     */
    pub fn auth(user: &Account, flags: RunFlags) -> bool {
        if let Some(hash) = getspnam(user.name()) {
            let pwd = ask_password(PROMPT_TEXT, flags);
            
            if let Some(user_hash) = crypt(&pwd, &hash) {
                return time_compare(&user_hash, &hash);
            }
            
        } else {
            errx!(1, "auth: {}", MSG_IO_USER_DB);
        }
    
        false
    }
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
pub fn authenticate(user: &Account, target: &Account, flags: RunFlags) -> bool {
    if user.uid() == 0 || (target.uid() == user.uid()
                        && (target.gid() == user.gid() || user.is_member(&target.gid().to_string()))) {
                            
        return true;
        
    } else if (flags & RunFlags::AUTH_NO_PROMPT) != RunFlags::NONE 
            && (flags & RunFlags::AUTH_STDIN) == RunFlags::NONE {
            
        return false;
        
    } else if !user.is_member(AUTH_GROUP) {
        return false;
    }

    feat::auth(&user, flags)
}


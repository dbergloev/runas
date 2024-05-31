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
     *
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
     *
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
 *
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


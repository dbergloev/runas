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
 * User, Group, and Account abstractions for system identity management.
 *
 * This module provides safe Rust wrappers around POSIX user and group database
 * access, integrating `libc` and `nix::unistd` to retrieve and verify account
 * information. It defines three simple structs:
 *
 *  - `User`: represents a system user (name, UID, primary GID)
 *  - `Group`: represents a system group (name, GID)
 *  - `Account`: a composite of `User` and primary `Group`
 *
 * These structures are used throughout `runas` to represent both the invoking
 * and target user identities during authentication and privilege switching.
 * ```
 */

use super::shared::*;
use std::ffi::CString;
use nix::unistd::{
    User as C_User, 
    Group as C_Group,
    Uid as C_Uid,
    Gid as C_Gid,
    getuid
};
use libc::{
    c_int, 
    gid_t,
    getgrouplist
};

/**
 * Represents a system group, including name and numeric ID.
 */
pub struct Group {
    pub(in self) gid: u32,
    pub(in self) name: String
}

/**
 * Represents a system user, including name, UID, and primary group ID.
 */
pub struct User {
    pub(in self) uid: u32,
    pub(in self) gid: u32,
    pub(in self) name: String
}

/**
 * Represents a combined user and group account (primary identity).
 */
pub struct Account {
    pub(in self) user: User,
    pub(in self) group: Group
}

/**
 *
 */
impl User {
    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.name }
    
    /**
     * Return the user ID
     */
    pub fn uid(&self) -> u32 { self.uid }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> u32 { self.gid }

    /**
     * Create a user from a name or UID string.
     *
     * Accepts either a username (e.g., `"bob"`) or a numeric UID (e.g., `"1000"`).
     * Validates the entry against the system database and returns `Some(User)` if found.
     *
     * Aborts the process with `errx!()` if the system user database cannot be queried.
     */
    pub fn from(user: &str) -> Option<Self> {
        let uinfo: Option<C_User>;
        
        if user.chars().all(char::is_numeric) {
            let parsed_uid = user.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
            let uid = C_Uid::from_raw(parsed_uid);

            // Even though we have a UID, we validate it.
            uinfo = C_User::from_uid(uid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        
        } else {
            uinfo = C_User::from_name(user).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        }
        
        if let Some(uinfo) = uinfo {
            return Some( 
                        User { 
                            gid: uinfo.gid.as_raw(),
                            uid: uinfo.uid.as_raw(),
                            name: uinfo.name 
                        } 
                   );
        }
        
        None
    }
}

/**
 *
 */
impl Group {
    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.name }
    
    /**
     * Return the user primary group ID
     */
    pub fn gid(&self) -> u32 { self.gid }
    
    /**
     * Create a group from a name or GID string.
     *
     * Accepts either a group name or a numeric GID.
     * Validates the entry against the system database and returns `Some(Group)` if found.
     */
    pub fn from(group: &str) -> Option<Self> {
        let ginfo: Option<C_Group>;
        
        if group.chars().all(char::is_numeric) {
            let parsed_gid = group.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
            let gid = C_Gid::from_raw(parsed_gid);

            // Even though we have a GID, we validate it.
            ginfo = C_Group::from_gid(gid).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        
        } else {
            ginfo = C_Group::from_name(group).unwrap_or_else(|_e| { errx!(1, MSG_IO_USER_DB); });
        }
        
        if let Some(ginfo) = ginfo {
            return Some( 
                        Group { 
                            gid: ginfo.gid.as_raw(),
                            name: ginfo.name 
                        } 
                   );
        }
        
        None
    }
}

/**
 *
 */
impl Account {
    /**
     * Return the user name
     */
    pub fn name(&self) -> &str { &self.user.name }
    
    /**
     * Return the user ID
     */
    pub fn uid(&self) -> u32 { self.user.uid }
    
    /**
     * Return the user group ID
     */
    pub fn gid(&self) -> u32 { self.group.gid }

    /**
     * Return the user object
     */
    pub fn user(&self) -> &User { &self.user }
    
    /**
     * Return the group object
     */
    pub fn group(&self) -> &Group { &self.group }
    
    /**
     *
     */
    pub fn set_user(&mut self, user: User) {
        self.user = user;
    }
    
    /**
     *
     */
    pub fn set_group(&mut self, group: Group) {
        self.group = group;
    }

    /**
     * Get an instance of the current executing account
     */
    pub fn current() -> Option<Self> {
        let uid = getuid().as_raw().to_string();
        Self::from(&uid)
    }
    
    /**
     * Construct a new `Account` from a username or UID string.
     *
     * Looks up both user and primary group entries and combines them into a full `Account`.
     */
    pub fn from(user: &str) -> Option<Self> {
        if let Some(user) = User::from(user) {
            if let Some(group) = Group::from(&user.gid.to_string()) { 
                return Some(Account {user, group});
            }
        }
        
        None
    }
    
    /**
     * Check whether this account is a member of the specified group.
     *
     * The `group` argument may be a name or numeric GID.
     * Root (UID 0) is treated as a member of all groups.
     */
    pub fn is_member(&self, group: &str) -> bool {
        // Root belongs to everything
        if self.user.uid == 0 {
            return true;
        }
        
        // Initialize the group list
        let groups_len: usize = 32;
        let mut groups = vec![0 as gid_t; groups_len];
        
        // Convert some values into C types
        let c_username = CString::new(&*self.user.name).unwrap_or_else(|_e| { errx!(1, MSG_PARSE_CSTRING); });
        let mut c_len = groups_len as c_int;
        
        for i in 0..2 {
            // Extract groups into the vector
            let ret = unsafe {
                getgrouplist(
                    c_username.as_ptr(),
                    self.group.gid as gid_t,
                    groups.as_mut_ptr(),
                    &mut c_len,
                )
            } as i32;
            
            if ret == -1 {
                if i == 0 {
                    // If the buffer was too small, resize and try again
                    groups.resize(2 * groups_len, 0 as gid_t);
                    continue;
                }
                
                errx!(1, MSG_IO_USER_DB);
            }
            
            break;
        }
        
        // Let's see if we can find the group we require
        if group.chars().all(char::is_numeric) {
            let parsed_gid = group.parse::<u32>().unwrap_or_else(|_e| { errx!(1, MSG_PARSE_NUM); });
            
            for gid in groups {
                if gid == parsed_gid {
                    return true;
                }
            }
        
        } else {
            for gid in groups {
                let c_gid = C_Gid::from_raw(gid);
            
                if let Ok(gopt) = C_Group::from_gid(c_gid) {
                    if let Some(gname) = gopt {
                        if gname.name == group {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
}


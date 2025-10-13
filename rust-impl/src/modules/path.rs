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

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::ffi::CString;

use std::path::{
    Path, 
    PathBuf
};

/**
 *
 */
pub fn find_executable(cmd: &str, extra_envp: &[CString]) -> Option<PathBuf> {
    let path = Path::new(cmd);

    // Case 1: already absolute
    if path.is_absolute() {
        return if is_executable(path) {
            Some(path.to_path_buf())
        } else {
            None
        };
    }

    // Case 2: relative (contains /)
    if cmd.contains('/') {
        if let Ok(full) = fs::canonicalize(path) {
            if is_executable(&full) {
                return Some(full);
            }
        }
        return None;
    }

    // Case 3: search in current PATH
    if let Some(found) = search_path_var(cmd, env::var("PATH").ok().as_deref()) {
        return Some(found);
    }

    // Case 4: search any PATH= in provided envp
    for entry in extra_envp.iter().rev() {
        if let Ok(s) = entry.to_str() {
            if let Some(rest) = s.strip_prefix("PATH=") {
                if let Some(found) = search_path_var(cmd, Some(rest)) {
                    return Some(found);
                }
            }
        }
    }

    None
}

/**
 *
 */
fn is_executable(path: &Path) -> bool {
    path.is_file() && fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/**
 *
 */
fn search_path_var(cmd: &str, path_var: Option<&str>) -> Option<PathBuf> {
    if let Some(path_var) = path_var {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            
            let candidate = Path::new(dir).join(cmd);
            
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    
    None
}


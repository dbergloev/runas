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

#[macro_use]
extern crate runas;

use runas::modules::shared::*;
use runas::modules::user::{Group, Account};
use runas::modules::auth::authenticate;
use nix::unistd::{execvp, setuid, Uid};
use getopts::Options;
use atty::Stream;
use std::env;

macro_rules! cstr {
    ($str:expr) => {
        std::ffi::CString::new($str).unwrap_or_else(|_e| { errx!(1, "argv: {}", MSG_PARSE_CSTRING); })
    };
}

/**
 * A structure to store available options
 */
#[derive(PartialEq, Eq)]
struct Option {
    flag: &'static str,
    name: &'static str,
    desc: &'static str,
    val:  &'static str
}

const OPT_USER    : Option  =  Option { flag: "u",   name: "user",            desc: "Run process as the specified user name or ID",      val: "USER"  };
const OPT_GROUP   : Option  =  Option { flag: "g",   name: "group",           desc: "Run process as the specified group name or ID",     val: "GROUP" };
const OPT_SHELL   : Option  =  Option { flag: "s",   name: "shell",           desc: "Run $SHELL as the target user",                     val: EMPTY   };
const OPT_HELP    : Option  =  Option { flag: "h",   name: "help",            desc: "Display this help screen",                          val: EMPTY   };
const OPT_NONINT  : Option  =  Option { flag: "n",   name: "non-interactive", desc: "Non-interactive mode, don't prompt for password",   val: EMPTY   };
const OPT_STDIN   : Option  =  Option { flag: "S",   name: "stdin",           desc: "Read password from standard input",                 val: EMPTY   };
const OPT_VERSION : Option  =  Option { flag: "v",   name: "version",         desc: "Display version information and exit",              val: EMPTY   };
const OPT_ENV     : Option  =  Option { flag: EMPTY, name: "env",             desc: "Set environment variable",                          val: "ENV"   };

const OPTS: [Option; 8] = [OPT_USER, OPT_GROUP, OPT_SHELL, OPT_HELP, OPT_NONINT, OPT_STDIN, OPT_VERSION, OPT_ENV];

/**
 *
 */
fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] -- CMD", program);
    print!("{}", opts.usage(&brief));
}

/**
 *
 */
fn get_argv_options() -> Options {
    let mut opts = Options::new();
    
    for opt in OPTS {
        if opt.val == EMPTY {
            opts.optflag(opt.flag, opt.name, opt.desc);
        
        } else {
            opts.optopt(opt.flag, opt.name, opt.desc, opt.val);
        }
    }
    
    return opts;
}

/**
 *
 */
fn get_argv() -> Vec<std::ffi::CString> {
    let argv = vec![
        cstr!("systemd-run"),
        cstr!("--uid"), cstr!(EMPTY), // MUST be in this order
        cstr!("--quiet"),
        cstr!("-G"),
        cstr!("--send-sighup"),
        #[cfg(not(feature = "without_expand_env"))]
        cstr!("--expand-environment=false")
    ];

    return argv;
}

/**
 *
 */
fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut run_argv = get_argv();
    let opts = get_argv_options();
    let mut flags = RunFlags::NONE;
    let mut group_obj = None;
    let mut accnt_obj = None;
    
    let matches = match opts.parse(&argv[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&argv[0][..], opts);
            errx!(1, e);
        }
    };
    
    for opt in OPTS {
        if matches.opt_present(opt.name) {
            match opt {
                OPT_HELP => {
                    print_usage(&argv[0], opts);
                    return;
                }
            
                OPT_USER => {
                    let opt_value = matches.opt_str(opt.name).unwrap_or_else(|| {
                        errx!(1, "User was not suplied");
                    });
                    
                    accnt_obj = Account::from(&opt_value);
                    
                    if accnt_obj.is_none() {
                        errx!(1, "User {} is not valid", opt_value);
                    }
                }
                
                OPT_GROUP => {
                    let opt_value = matches.opt_str(opt.name).unwrap_or_else(|| {
                        errx!(1, "Group was not suplied");
                    });
                    
                    group_obj = Group::from(&opt_value);
                    
                    if group_obj.is_none() {
                        errx!(1, "Group {} is not valid", opt_value);
                        
                    } else {
                        run_argv.push(cstr!("--gid"));
                        run_argv.push(cstr!(opt_value));
                    }
                }
                
                OPT_VERSION => {
                    #[cfg(feature = "use_pam")]
                    println!("{} {} PAM", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                    
                    #[cfg(not(feature = "use_pam"))]
                    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                    
                    return;
                }
                
                OPT_ENV => {
                    let opt_value = matches.opt_str(opt.name).unwrap_or_else(|| {
                        errx!(1, "Missing environment variable");
                    });
                    
                    run_argv.push(cstr!("--setenv"));
                    run_argv.push(cstr!(opt_value));
                }
                
                OPT_SHELL => flags |= RunFlags::SHELL,
                OPT_STDIN => flags |= RunFlags::AUTH_STDIN,
                OPT_NONINT => flags |= RunFlags::AUTH_NO_PROMPT,
                
                _ => NULL
            }
        }
    }
    
    // Create selected user account or set it to root if not set via argv
    let user = Account::current().unwrap_or_else(|| { errx!(1, "Failed to initialize current user"); });
    let mut target = if let Some(account) = accnt_obj { account } else {
        Account::from("0").unwrap_or_else(|| { errx!(1, "Failed to initialize default user"); })
    };
    
    // If we have a different gid in argv, update the group
    if let Some(group) = group_obj {
        target.set_group(group);
    }
    
    // Do some last systemd-run configuration
    if (flags & RunFlags::SHELL) != RunFlags::NONE {
        if matches.free.len() > 0 {
            errx!(1, "Not expecting arguments with the --shell option");
            
        } else if (flags & RunFlags::AUTH_STDIN) != RunFlags::NONE {
            errx!(1, "The --stdin option is not allowed combined with the --shell option");
        }
        
        run_argv.push(cstr!("--shell"));
        run_argv.push(cstr!("--scope"));
    
    } else {
        if atty::is(Stream::Stdout) 
                && atty::is(Stream::Stderr) 
                && atty::is(Stream::Stdin) {
        
            run_argv.push(cstr!("--pty"));
            
        } else {
            run_argv.push(cstr!("--pipe"));
        }
        
        run_argv.push(cstr!("--service-type=exec"));
        run_argv.push(cstr!("--wait"));
        run_argv.push(cstr!("--"));
    }
    
    // Set the uid that systemd-run should use
    run_argv[2] = cstr!(target.uid().to_string());
    
    // Copy all of the argv that systemd-run should execute
    for opt in matches.free {
        run_argv.push(cstr!(opt));
    }
    
    // Authenticate the current user, the target user and spawn systemd
    if authenticate(&user, &target, flags) {
        // Set current UID to root to disable polkit authentication
        if !setuid( Uid::from_raw(0) ).is_ok() {
            errx!(1, "Failed to set uid");
        }
    
        execvp(&run_argv[0], &run_argv).expect("Failed to spawn process");
        
        // We should never reach this point
    }

    errx!(1, "Authentication failed");
}


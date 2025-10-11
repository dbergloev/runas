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
 * runas — A systemd-integrated privilege and user switching utility.
 *
 * This program is a secure, minimal replacement for classic `sudo`-style tools.
 * It performs user authentication and delegates the final process execution to
 * `systemd-run`, taking advantage of systemd’s service supervision, cgroup isolation,
 * and clean environment handling. 
 *
 * Unlike traditional privilege tools, `runas` does not execute processes directly.
 * After verifying authentication (via PAM or a custom backend), it constructs a
 * complete `systemd-run` command line and replaces itself with that process
 * using `execvp()`. This makes `runas` stateless after delegation, and ensures
 * that all executed commands are systemd-managed.
 *
 * The binary must run setuid-root, like `sudo`, since it temporarily raises privileges
 * to change UID before delegating to `systemd-run`. It does **not** maintain any root
 * privileges after exec; the invoked process is fully isolated in its own transient
 * systemd service.
 *
 * ### Command Flow
 * ```
 * runas  →  authenticate()  →  build argv  →  execvp("systemd-run", ...)
 * ```
 */

#[macro_use]
extern crate runas;

use runas::modules::auth::authenticate;
use runas::modules::shared::*;
use std::os::unix::ffi::OsStrExt;
use std::env;
use std::path::PathBuf;
use std::ffi::CString;
use atty::Stream;

use runas::modules::user::{
    Group, 
    Account
};

use nix::unistd::{
    execvp, 
    setuid, 
    Uid
};

use getopts::{
    Options,
    Matches
};

/**
 * Creates a `CString` from a Rust string literal or value, terminating the program on error.
 *
 * This macro safely converts a Rust `&str` or `String` into a null-terminated
 * `CString` suitable for C FFI calls (e.g., `execvp()` arguments).  
 */
macro_rules! cstr {
    ($str:expr) => {
        CString::new($str).unwrap_or_else(|_e| { 
            errx!(1, "argv: {}", MSG_PARSE_CSTRING); 
        })
    };
}

/**
 * A structure to store available options
 */
#[derive(PartialEq, Eq)]
struct CliOption {
    flag: &'static str,
    name: &'static str,
    desc: &'static str,
    val:  &'static str
}

const OPT_USER    : CliOption  =  CliOption { flag: "u",   name: "user",            desc: "Run process as the specified user name or ID",      val: "USER"  };
const OPT_GROUP   : CliOption  =  CliOption { flag: "g",   name: "group",           desc: "Run process as the specified group name or ID",     val: "GROUP" };
const OPT_SHELL   : CliOption  =  CliOption { flag: "s",   name: "shell",           desc: "Run $SHELL as the target user",                     val: EMPTY   };
const OPT_HELP    : CliOption  =  CliOption { flag: "h",   name: "help",            desc: "Display this help screen",                          val: EMPTY   };
const OPT_NONINT  : CliOption  =  CliOption { flag: "n",   name: "non-interactive", desc: "Non-interactive mode, don't prompt for password",   val: EMPTY   };
const OPT_STDIN   : CliOption  =  CliOption { flag: "S",   name: "stdin",           desc: "Read password from standard input",                 val: EMPTY   };
const OPT_VERSION : CliOption  =  CliOption { flag: "v",   name: "version",         desc: "Display version information and exit",              val: EMPTY   };
const OPT_ENV     : CliOption  =  CliOption { flag: EMPTY, name: "env",             desc: "Set environment variable",                          val: "ENV"   };

const ARGV_SCHEME: &[CliOption] = &[OPT_USER, OPT_GROUP, OPT_SHELL, OPT_HELP, OPT_NONINT, OPT_STDIN, OPT_VERSION, OPT_ENV];

/**
 * Prints the usage/help text based on the current command-line schema.
 */
fn print_usage(program: &str, argv_opt: &Options) {
    let brief: String = format!("Usage: {} [options] -- CMD", program);
    print!("{}", argv_opt.usage(&brief));
}

/**
 * Build and return a configured `getopts::Options` parser
 * matching the static argument schema in `ARGV_SCHEME`.
 */
fn get_argv_options() -> Options {
    let mut argv_opt = Options::new();
    
    for cli_opt in ARGV_SCHEME {
        if cli_opt.val == EMPTY {
            argv_opt.optflag(cli_opt.flag, cli_opt.name, cli_opt.desc);
        
        } else {
            argv_opt.optopt(cli_opt.flag, cli_opt.name, cli_opt.desc, cli_opt.val);
        }
    }
    
    return argv_opt;
}


/**
 * Constructs the initial `systemd-run` argument vector.
 * The UID placeholder (index 2) is later replaced dynamically
 * when the target user is resolved.
 */
fn get_argv() -> Vec<std::ffi::CString> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "use_run0")] {
            let argv = vec![
                cstr!("run0"),
                cstr!("--user"), cstr!(EMPTY),      // MUST be in this order
                cstr!("--shell-prompt-prefix="),    // Remove the stupid SuperUser icon
                cstr!("--background=")              // Remove the annoying red background
            ];
        
        } else {
            let argv = vec![
                cstr!("systemd-run"),
                cstr!("--uid"), cstr!(EMPTY), // MUST be in this order
                cstr!("--quiet"),
                cstr!("-G"),
                cstr!("--send-sighup"),
                cstr!("--same-dir"),
                #[cfg(not(feature = "without_expand_env"))]
                cstr!("--expand-environment=false")
            ];
        }
    }

    return argv;
}

/**
 * Program entry point.
 *
 * 1. Parses command line arguments
 * 2. Authenticates user credentials
 * 3. Builds `systemd-run` command argv
 * 4. Executes it with appropriate privileges
 *
 * Exits immediately on error via `errx!()`.
 */
fn main() {
    let     argv_in:   Vec<String>      = env::args().collect();
    let mut argv_out:  Vec<CString>     = get_argv();
    let     argv_opt:  Options          = get_argv_options();
    let mut flags:     RunFlags         = RunFlags::NONE;
    let mut group_obj: Option<Group>    = None;
    let mut accnt_obj: Option<Account>  = None;
    
    let argv_parsed: Matches = match argv_opt.parse(&argv_in[1..]) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&*argv_in[0], &argv_opt);
            errx!(1, e);
        }
    };
    
    for cli_opt in ARGV_SCHEME {
        if argv_parsed.opt_present(cli_opt.name) {
            match *cli_opt {
                OPT_HELP => {
                    print_usage(&argv_in[0], &argv_opt);
                    return;
                }
            
                OPT_USER => {
                    let cli_value: String = argv_parsed.opt_str(cli_opt.name).unwrap_or_else(|| {
                        errx!(1, "User was not suplied");
                    });
                    
                    accnt_obj = Account::from(&cli_value);
                    
                    if accnt_obj.is_none() {
                        errx!(1, "User {} is not valid", cli_value);
                    }
                }
                
                OPT_GROUP => {
                    let cli_value: String = argv_parsed.opt_str(cli_opt.name).unwrap_or_else(|| {
                        errx!(1, "Group was not suplied");
                    });
                    
                    group_obj = Group::from(&cli_value);
                    
                    if group_obj.is_none() {
                        errx!(1, "Group {} is not valid", cli_value);
                        
                    } else {
                        cfg_if::cfg_if! {
                            if #[cfg(feature = "use_run0")] {
                                argv_out.push(cstr!("--group"));
                            
                            } else {
                                argv_out.push(cstr!("--gid"));
                            }
                        }

                        argv_out.push(cstr!(cli_value));
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
                    let cli_value: String = argv_parsed.opt_str(cli_opt.name).unwrap_or_else(|| {
                        errx!(1, "Missing environment variable");
                    });
                    
                    argv_out.push(cstr!("--setenv"));
                    argv_out.push(cstr!(cli_value));
                }
                
                OPT_SHELL => flags |= RunFlags::SHELL,
                OPT_STDIN => flags |= RunFlags::AUTH_STDIN,
                OPT_NONINT => flags |= RunFlags::AUTH_NO_PROMPT,
                
                _ => NULL
            }
        }
    }
    
    // Create selected user account or set it to root if not set via argv
    let user: Account = Account::current().unwrap_or_else(|| { 
        errx!(1, "Failed to initialize current user"); 
    });
    
    // Get declared target or assume root
    let mut target: Account = if let Some(account) = accnt_obj { 
        account 
    } else {
        Account::from("0").unwrap_or_else(|| { 
            errx!(1, "Failed to initialize default user"); 
        })
    };
    
    // If we have a different gid in argv, update the group
    if let Some(group) = group_obj {
        target.set_group(group);
    }
    
    // Do some last systemd-run configuration
    if (flags & RunFlags::SHELL) != RunFlags::NONE {
        if argv_parsed.free.len() > 0 {
            errx!(1, "Not expecting arguments with the --shell option");
            
        } else if (flags & RunFlags::AUTH_STDIN) != RunFlags::NONE {
            errx!(1, "The --stdin option is not allowed combined with the --shell option");
        }

        cfg_if::cfg_if! {
            if #[cfg(not(feature = "use_run0"))] {
                argv_out.push(cstr!("--shell"));
                argv_out.push(cstr!("--scope"));
                
            } else {
                let path: Result<PathBuf, _> = env::current_dir();
            
                if let Ok(cwd) = path {
                    argv_out.push(cstr!("--chdir"));
                    argv_out.push(cstr!(
                        cwd.as_os_str().as_bytes()
                    ));
                }
            }
        }
    
    } else {
        if atty::is(Stream::Stdout) 
                && atty::is(Stream::Stderr) 
                && atty::is(Stream::Stdin) {
        
            argv_out.push(cstr!("--pty"));
            
        } else {
            argv_out.push(cstr!("--pipe"));
        }
        
        cfg_if::cfg_if! {
            if #[cfg(not(feature = "use_run0"))] {
                argv_out.push(cstr!("--service-type=exec"));
                argv_out.push(cstr!("--wait"));
            }
        }
        
        argv_out.push(cstr!("--"));
    }
    
    // Set the uid that systemd-run should use
    argv_out[2] = cstr!(target.uid().to_string());
    
    // Copy all of the argv that systemd-run should execute
    for opt in argv_parsed.free {
        argv_out.push(cstr!(opt));
    }
    
    // Authenticate the current user, the target user and spawn systemd
    if authenticate(&user, &target, flags) {
        // Set current UID to root to disable polkit authentication
        if !setuid( Uid::from_raw(0) ).is_ok() {
            errx!(1, "Failed to set uid");
        }
    
        execvp(&argv_out[0], &argv_out).expect("Failed to spawn process");
        
        // We should never reach this point
    }

    errx!(1, "Authentication failed");
}


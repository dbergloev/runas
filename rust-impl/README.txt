# RunAS implementation

The issues pointed out with `run0` is not that it does not work without `setuid`. It's the fact that they make it their main claim and purpose for it when it is not true. Running `sudo` behaviour through systemd has many other bennefits, but their "implementation" is poorly done and lacking. `runas` utilizes `systemd-run` but deals with the authentication rather than handing it of to polkit. This means that you get a proper prompt in the shell, just like with sudo or doas. It also properly implements most of the features that is supported by sudo and it can be symlinked or renamed as required. 

__Features__

| Options               | Value   | Description                                     |
| --------------------- | ------- | ----------------------------------------------- |
| -s, --shell           |         | Run $SHELL as the target user                   |
| -u, --user            | USER    | Run process as the specified user name or ID    |
| -g, --group           | GROUP   | Run process as the specified group name or ID   |
| -h, --help            |         | Display help screen                             |
|     --env             | VAR=VAL | Set environment variable                        |
| -n, --non-interactive |         | Non-interactive mode, don't prompt for password |
| -S, --stdin           |         | Read password from standard input               |
| -v, --version         |         | Display version information and exit            |
| --                    |         | Stop processing command line arguments          |

Currently there is no file similar to `/etc/sudoers`, but since this is using it's own authentication, it is possible to add this feature at some point. For now it statically uses the `wheel` group.

> This is meant as a fun little project. Although I have some knolege in this erea, I am not a security expert and small mistakes can lead to huge consequences. It should be safe enough to use, but do so at your own peril.

## Timestamp

When built without PAM, `runas` will not have the timestamp feature that sudo does where it remembers a login for a few minutes. The way `sudo` and others do this is kind of hacky using modified time on files and such, which has a lot of potential for security issues if not done right. As such it will not be implemented.

PAM has a module called `pam_timestamp` that implements this feature when authenticating through PAM. The way it works is mostly the same, but it has had time to mature and a lot of eyes has gone through the code. If this feature is a must, then it's best to use it through PAM.

## Build

By default `runas` will access the `shadow` file to authenticate users. You can change this to use PAM instead by adding the `use_pam` feature.

```sh
RUSTFLAGS="-l pam" cargo build --features use_pam
```

> You must manually add `-l pam` to the `RUSTFLAGS` environment variable. Sadly there is no way to do this automatically via `cargo.toml` or `build.rs`. 

Runas will also use the `--expand-environment` option in systemd-run which is set to `false`. This option is however fearily new and is not available in many currently used versions of systemd. As such you can build runas without this option by setting the `without_expand_env` feature. This will make runas compatible with older versions of systemd.


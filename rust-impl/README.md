# RunAS implementation

This can be build as an authentication front-end for `run0` or `systemd-run` directly. It can also be built as a true privilege-escalation utility that uses it's own implementation similar to `sudo`, `doas` etc. It provides a uniformed standard across all implementations, although some things like environment setup may vary depending on systemd's way of handling things across `run0` vs `systemd-run`. 

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


__Build Features__

| Flag               | Description                                                            |
| ------------------ | ---------------------------------------------------------------------- |
| use_pam            | This will build runas with PAM support.                                |
| backend_run0       | This will build runas to target run0 instead of systemd-run directly   |
| backend_scopex     | This will build runas with it's own backend implementation             |
| without_expand_env | This will build runas without --expand-environment=false (systemd-run) |

__scopex__  
Does not involve systemd-run at all. Uses it's own implementation for setting up environment, launching processes, deals with PAM sessions etc. 

__run0__  
By default runas will use `systemd-run` to launch processes. One problem with this is that the `--shell` option in `systemd-run` does not launch login shells, but rather just launch a shell in the current context as the specified user. This affects `runas -s`. Also since `systemd-run` does not have any way of changing the targets `argv[0]` e.g. `exec -a`, it's not possible to launch a login shell manually, at least not the proper way using `-/bin/SHELL`. Even if it was, it's not the task of this program. Runas works as an authenticator and nothing more. It authenticates a user and sets up systemd to deal with the rest. By adding the feature flag `use_run0`, runas will be build to target `run0` instead of `systemd-run`. Both targets `run.c`, but it gets configured differently depending on which one is used. Using `run0` a shell will be launched as a proper login shell. One important thing to note through is that `run0` is measurably slower than `systemd-run`. 

## /etc/sudoers

There are no files similar to `/etc/sudoers`, `/etc/doas.conf` etc. and there will properly never be. At least not without a very good reason. Large feature sets only lead to more complexity which in turn lead to more bugs and mistakes. We do not want errors and mistakes in something like this.

Runas will target the `wheel` group. This is the original super user group and there is no reason to target anything else or invent new group names on regular setups.

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


# RunAS implementation

This is an actual alternative to `sudo` that utilizes `systemd-run` while bypassing `polkit` by implementing it's own authentication similar to `sudo`. It also provides a lot more compatiblity with `sudo` compared to systemd's own `run0` attempt and it can be symlinked or renamed as required.

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

> This is meant as a fun little project. Although I have some knolege in this erea, I am not a security expert or the great and almightly C programmer. Do not use this on any important system. Most of the execution part is handed to `systemd` to deal with, but this program still deals with the authentication part. Any mistakes could result in anyone being able to gain full privileges. Currentl my eyes and my eyes alone has read through this code and I use glasses.

## Timestamp

When built without PAM, `runas` will not have the timestamp feature that sudo does where it remembers a login for a few minutes. The way `sudo` and others do this is kind of hacky using modified time on files and such, which has a lot of potential for security issues if not done right. As such it will not be implemented when built without PAM support.

PAM has a module called `pam_timestamp` that implements this feature when authenticaing through PAM. The way it works is mostly the same, but it has had time to mature and a lot of eyes has gone through the code. If this feature is a must, then it's best to use it through PAM.

## Build

To build and install `runas` clone the project and run the following:

```sh
make
sudo make install
```

## PAM

To add PAM support you will need to build this with `-DRUNAS_AUTH_PAM`. You will also need to add and configure a PAM file `/etc/pam.d/runas`, but this is outside the scope of this README since these will vary between various distributions. 


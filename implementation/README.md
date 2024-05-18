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

There is also the possibility for future PAM integration. Currently it simply accesses the `shadow` file directly.

> This is meant as a fun little project. Although I have some knolege in this erea, I am not a security expert or the great and almightly C programmer. Do not use this on any important system. Most of the execution part is handed to `systemd` to deal with, but this program still deals with the authentication part. Any mistakes could result in anyone being able to gain full privileges. Currentl my eyes and my eyes alone has read through this code and I use glasses.

## Timestamp

Currently `runas` will not remember previous authentications. The way `sudo` and others do this is kind of hacky using modified time on files and such, which has a lot of potential for security issues if not done right. I am not even gonna pretend to know enough about all of the ways this can be exploided to even try to implement this from sratch. Maybe with a future PAM integration it can be managed through PAM instead.

## Build

To build and install `runas` clone the project and run the following:

```sh
make
sudo make install
```


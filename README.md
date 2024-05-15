# RunAs

Systemd is introducing `run0` in version `256` which according to themselves would be a replacement to things like `sudo` and `doas`. One of the key advantaged, according to their own [documentation](https://github.com/systemd/systemd/blob/v256-rc2/man/run0.xml), is that their implementation does not require `setuid` which would add more security _(More about why this is not true)_.

Some people have gotten the wrong idea that this is a new tool, which is not the case. Systemd has a feature called `systemd-run` that allows you to run services, programs and more with a specified user id. The `run0` is simply a symlink to `systemd-run` which in turn adapts a few additional functionallity when used through the symlink, like being compatible with `sudo` arguments like `-u` _(More about why this is pointless)_. 

On the surface this seams like a great idea. For one, systemd will launch processes run by `systemd-run` within it's own process hierarchy, meaning that you will get a clean process without reused environment variables and such while also having systemd manage and cleanup everything being run through this process. And all of this without the need for `setuid` _(Again, not true)_.

### SetUID

The `setuid` "feature" in Linux allows you to execute a program with the privileges of the program files owner. So if `root` owns the file then any user can execute the program as `root` without requiring any authorization. It's a terrible design and only requires a single bit to be set on the file. But that is how `sudo` works. Being owned by root it can elevate any user by executing commands for them. However `sudo` does implement authorization and rules that must be validated before it allows users to run anything. 

Systemd's `run0` should fix this issue, but sadly it does not. It's true that `run0` or `systemd-run` itself does not rely on `setuid`. However it does use `polkit` for authorization which in turn requires `setuid`. The security implications of `setuid` is not a matter of a particular program like `sudo` using it, but the fact that this feature is even available to begin with. For `run0` to have any meaningful affect on this, it should be able to function with `setuid` being disabled on the system, but that would break `run0` due to it's dependency on `polkit`. If `setuid` is enabled on a system, you may as well just use `sudo` which in it self does not introduce much more of security risk than `polkit` or `systemd`. 

Their own docs state that `run0` would be able to work on systems that does not support `setuid`, but this is an outright lie as this issue has been pointed out to them.

### Pointless compatiblity

When using `systemd-run` through the symlink `run0`, you get additional options for compatiblity with `sudo`. This includes arguments like `-u` to define a user whereas `systemd-run` would normally use `--uid`. But this is pointless seen as `run0` ONLY works through this path. If you try to symlink `/usr/bin/sudo` to `/usr/bin/run0` then those options will not be available and `sudo` would be executed as a regular `systemd-run` call expecting `--uid` rather than `-u`. If you cannot make the call to `sudo` backwards compatible with scripts and programs that uses it, then it's pointless to make the options backward compatible as you would have to make changes to scripts and programs anyway.

### Scope

This is another issue with compatibility. Because systemd is actually a service manager, it's build to strickly deal with processes and their children. By default a systemd process, when being terminated, will have all of it's children be terminated as well. This means that if you run a root shell using `run0` and then launch `screen` or `tmux`, then start a task of some sort and then lieves and exist the shell, systemd will terminate everthing, including your `screen` or `tmux` instance and the task it was dealing with. If they designed `run0` as a new way of doing things, sure you would know to deal with this particular scenario and luanch a `--scope` process. But they are trying to mimic `sudo` _(E.g. -u for an example)_ in an attempt to make it less transparent what is being used. Anyone expecting `sudo` behaviour will run into problems.

### Authorization and Rules

In `sudo` you would normally use `/etc/sudoers` or `/etc/doas.conf` for `doas` to define rules for specific users and groups. The `run0` option has no way of it's own to create rules. Instead it relies on polkit targeting `org.freedesktop.systemd1.manage-units` rather than something like `org.freedesktop.systemd1.run0`.

### GUI vs TUI

Polkit will most often use your Desktop UI to prompt for password. So unlike things like `sudo`, unless you are authenticating via SSH or a TTY, you will get a GUI prompt rather than being prompted in the shell when invoking `run0`. Polkit for some reason has no simple way of changing this within a specific rule and even if they did, you would change this behavior for most of systemd, since `run0` can't be targeted specifically. 

### Sumary

The "new" `run0` is a pointless and poorly tought out attempt to fix an issue, that in the end, it does not even try to fix. Instead it just introduces more issues and complexity to a task that should be simple to use.

## This Repo

In this repo are included the `runas` command. It's custom version of `run0` that deals with some of the issues arised and is much closer to `sudo` behaviour than `run0`. It's not meant to be used, seen as the whole idea of `run0` is stupid, and this script is more a proff of concept to show just how terrible systemd and polkit is to deal with this task, unless they actually implement a REAL solution into systemd rather than this pointless symlink.

So let's go over some of the issues in this script that is more or less avoidable. 

 1. Like with `run0` this does not fix the issue with `setuid`. 
 2. In order to mimic `sudo` behavior, `runas -s` will launch `$SHELL` in a `--scope`. This in turn is not really possible with systemd if you are elivating the users privileges at the same time. So to make this work, a dual call to systemd is required, first to elivate the privileges and then to launch a `--scope` process with those privileges.
 3. The `--scope` is only being applied to the `-s` option. This means that if you manually launch a shell with `runas bash` and then run `tmux`, it will fail if you detach and exists the shell.
 4. If you are not elivating privileges, but instead try to run a program using the same uid as your active uid, then there is no call to systemd and the program is just executed directly, just like with `sudo`. But this also provides two different behaviours. One where you invoke systemd and start a process in the systemd process hierarchy and another behaviour where you start a process in the current process hierarchy. The only other solution would be to have a user authenticate even when they are trying to run something as themselves.
 
Some of the good things. 

 1. Does not rely on version `256`. This can be used on any systemd version that supports `systemd-run`.
 2. MUCH closer to real `sudo` behaviour than `run0`.
 3. Can easily be symlinked from `/usr/bin/sudo` to `/usr/bin/runas`.
 4. No stupid background collering.
 5. Much better name.
 
## Conclusion

`run0` will not replace `sudo`. Not until the developers of systemd actually makes an effort and does it right. 60% of these issues can be traced to `polkit`, but that is not an issue with polkit. It's an issue with tools using it for things that it was not meant or designed for. Also the remaining 40% is all systemd.


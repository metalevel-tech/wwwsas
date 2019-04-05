# Update log

## Features, presented in the master branch, not presented in the [stable.v.4]65] branch

* ...

## Features, presented in [stable.v.4][6], not presented in the [stable.v.3][5] branch

* Full integration with [`www.abuseipdb.com`](https://www.abuseipdb.com) [API V2](https://docs.abuseipdb.com/).

* OWASP ModSecurity CRS - [`v3.2/dev`](https://github.com/SpiderLabs/owasp-modsecurity-crs) integration: the missing `update.py` were copied from the [`v3.0/master`](https://github.com/SpiderLabs/owasp-modsecurity-crs) branch to the current repository.

* The variables `$EMAIL_BODY` and `$EMAIL_BODY_PLAIN` now refer to unique files, that are removed after the main script finish.

* The installation script `SETUP` is compatible with Ubuntu 18.04: the package `ifupdown` must be manually installed: `sudo apt install ifupdown`.

* For more details check [stable.v.4/README.UPDATE.md][7].

### OWASP ModSecurity CRS - v3.2/dev

**DONE!**

At the moment the repository of [`v3.2/dev`](https://github.com/SpiderLabs/owasp-modsecurity-crs) doesn't contain the script `util/upgrade.py`, so it is included in the current project. The source ot this script is the `v3.0/master`. So if you need to deploy it manually use:

````bash
sudo cp {/etc/www-security-assistant/file-system,}/etc/modsecurity/owasp-modsecurity-crs/util/upgrade.py
````

### Unique *tmp/mail* files needed

**DONE!**

The following files should be unique temporary filed for each execution of the main script.

````bash
# This file will exists until next thread, it contains the content of the last email sent by the script
EMAIL_BODY="${WORK_DIR}/${WWW_SAS_FULL}.mail"
EMAIL_BODY_PLAIN="${WORK_DIR}/${WWW_SAS_FULL}.mail.plain"
````

Does they are used only in the main script? - Yes.

### Fail states on Ubuntu 18.04

**DONE!**

**Solution (applied in the SETUP file):**

On 18.04 `ifupdown` must be manually installed:

````bash
sudo apt install ifupdown
````

And everything other should be okay.

**Issue (and workaround that is not needed):**

  ````bash
  *** Setup Iptables SAVE and RESTORE at REBOOT *****

  Do you want to setup Iptables SAVE and RESTORE at REBOOT? [Yes] [Yes][No]:
  Accepted input: Yes

  ln: failed to create symbolic link '/etc/network/if-post-down.d/000-iptables-save': No such file or directory
  The following command was executed: ln -s '/etc/www-security-assistant/iptables-save.sh' '/etc/network/if-post-down.d/000-iptables-save'
  The following command was executed: ln -s '/etc/www-security-assistant/iptables-restore.sh' '/etc/network/if-pre-up.d/000-iptables-restore'

  *** Setup Ipset SAVE and RESTORE at REBOOT *****

  Do you want to setup Ipset SAVE and RESTORE at REBOOT? [Yes] [Yes][No]:
  Accepted input: Yes

  ln: failed to create symbolic link '/etc/network/if-post-down.d/000-ipset-save': No such file or directory
  The following command was executed: ln -s '/etc/www-security-assistant/ipset-save.sh' '/etc/network/if-post-down.d/000-ipset-save'
  The following command was executed: ln -s '/etc/www-security-assistant/ipset-restore.sh' '/etc/network/if-pre-up.d/000-ipset-restore'
  ````

* To setup `iptables` save and restore on Ubuntu 18.04 - [reference](https://askubuntu.com/a/1072948/566421):

  ````bash
  sudo apt install iptables-persistent netfilter-persistent

  netfilter-persistent save
  netfilter-persistent start
  ````

  According to that we should modify `iptables-save.sh` and `iptables-restore.sh` in this way

  ````bash
  $ cat iptables-save.sh
  #!/bin/sh

  /sbin/iptables-save > /etc/www-security-assistant/iptables.current-state.conf
  /sbin/iptables-save > /etc/iptables/rules.v4

  /sbin/ip6tables-save > /etc/www-security-assistant/ip6tables.current-state.conf
  /sbin/ip6tables-save > /etc/iptables/rules.v6

  /usr/sbin/netfilter-persistent save

  exit 0

  $ cat iptables-restore.sh
  #!/bin/sh

  /usr/sbin/netfilter-persistent

  #/sbin/iptables-restore < /etc/www-security-assistant/iptables.current-state.conf
  /sbin/iptables-restore < /etc/iptables/rules.v4

  #/sbin/iptables-restore < /etc/www-security-assistant/ip6tables.current-state.conf
  /sbin/ip6tables-restore < /etc/iptables/rules.v6

  exit 0
  ````

* New files to be maintained: `/etc/iptables/rules.v4` `/etc/iptables/rules.v6`.

* The files `iptables-save.sh` `iptables-restore.sh` are updated.

* **In the `SETUP` script the creation of the above sym-links must be suspended. Also `apt install iptables-persistent netfilter-persistent` must be applied on that place.**

* **Must be found a proper solution for `ipset` save/restore.** At the moment when it is used it breaks `netfilter-persistent start` at boot time. The current workaround is the following cron job:

  ````bash
  $ cat /etc/cron.d/wwwsas-iptables-ipset-restore
  @reboot root sleep 5 && "/etc/www-security-assistant/ipset-restore.sh" >/dev/null 2>&1 && "/etc/www-security-assistant/iptables-restore.sh" >/dev/null 2>&1
  ````

  Actually we do not care whether `iptables` state is saved on shut down, because we've saved them when it is needed. So...

## Features, presented in [stable.v.3][5], not presented in the [stable.v.2][3] branch

* Full integration with [`www.abuseipdb.com`](https://www.abuseipdb.com).

## Features, presented in [stable.v.2][3], not presented in the [stable.v.1][2] branch

* The script `modsecurity-whitelist-rule-generator.bash` is added.
* The satellite script `flood-detector.bash` is added.
* Handling some error messages and indeterminate behavior.
* Send HTML and/or plain text emails.
* Semi-integration with [`www.abuseipdb.com`](https://www.abuseipdb.com).
* Completely new installation process that uses `git` and the `SETUP` script.

**Notes to the branch [stable.v.2][3]**:

* The new `SETUP` script is not available for the branches [ask_ubuntu][1] and [stable.v.1][2].
* The configuration file `www-security-assistant.conf`, now, plays more significant role - the main script an all satellite scripts use common settings.
* The verbose explanations about the installation process will be kept in the file [README.OLD.md][4]

## Features, presented in [stable.v1][2], not presented in the [ask_ubuntu][1] branch

* Configuration file.
* Installation script (depreciated in the next version).

 [1]: https://github.com/pa4080/www-security-assistant/tree/ask_ubuntu
 [2]: https://github.com/pa4080/www-security-assistant/tree/stable.v.1
 [3]: https://github.com/pa4080/www-security-assistant/tree/stable.v.2
 [4]: https://github.com/pa4080/www-security-assistant/blob/stable.v.2/README.OLD.md
 [5]: https://github.com/pa4080/www-security-assistant/tree/stable.v.3
 [6]: https://github.com/pa4080/www-security-assistant/tree/stable.v.4
 [7]: https://github.com/pa4080/www-security-assistant/tree/stable.v.4/README.UPDATE.md

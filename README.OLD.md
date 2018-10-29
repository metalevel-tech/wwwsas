# WWW Security Assistant

This is a bundle of scripts that can helps you with malicious IP addresses handling within Apache2 and Ubuntu environment.
The core of the bundle was inspired by a [question](https://askubuntu.com/a/922144/566421) on AskUbuntu.com.

The current project covers the following topics, that are involved into a complete mechanism. It is all about **How to increase Apache2 security within Ubuntu 16.04**.

1. [WWW Security Assistant Script (WWWSAS) ► Iptables](#www-security-assistant-script-wwwsas--iptables)
2. [Iptables – Basic Configuration – Save and Restore](#iptables--basic-configuration--save-and-restore)
3. [ModEvasive for Apache2](#modevasive-for-apache2)
4. [ModEvasive ► WWWSAS ► Iptables](#modevasive--wwwsas--iptables)
5. [ModSecurity 2.9 for Apache2](#modsecurity-29-for-apache2)
6. [ModSecurity OWASP Core Rule Set 3.x](#modsecurity-owasp-core-rule-set-3x)
7. [ModSecurity Rules Whitelisting](#modsecurity-rules-whitelisting)
8. [ModSecurity Rules ► WWWSAS ► Iptables](#modsecurity-rules--wwwsas--iptables)
9. [WWWSAS Whitelist Rule Generator ► ModSecurity Rules Whitelisting](#wwwsas-whitelist-rule-generator--modsecurity-rules-whitelisting)
10. [ModSecurity and Apache Log Files](#modsecurity-and-apache-log-files)
11. [ModSecurity Log Files ► Fail2Ban ► Iptables](#modsecurity-log-files--fail2ban--iptables)
12. [ModSecurity GuardianLog ► HTTPD Guardian ► WWWSAS ► Iptables](#modsecguardianlog--httpd-guardian--wwwsas--iptables)
13. [ModSecurity GuardianLog ► HTTPD Custom Analyze ► WWWSAS ► Iptables](#modsecguardianlog--httpd-custom-analyze--wwwsas--iptables)
14. [WWWSAS Flood Detector ► WWWSAS ► Iptables](#wwwsas-flood-detector--wwwsas--iptables)
15. [HTTPS and Common Apache Security Tips](#https-and-common-apache-security-tips)

To be added:

* [Integrating with ClamAV](https://www.feistyduck.com/library/modsecurity-handbook-free/online/ch04-logging.html)
* Full integration with [`www.abuseipdb.com`](https://www.abuseipdb.com)

## WWW Security Assistant Script (WWWSAS) ► Iptables

Here is presented the script [**`www-security-assistant.bash`**][2]. It could help you with the handling of the malicious IP addresses. The script has two modes.

### Automatic mode

When an external program, as Apache's `mod_security`, provides a malicious `$IP` address. In this case, the syntax that invokes the script, should be:

  ````bash
  www-security-assistant.bash <ip-address> Guardian
  www-security-assistant.bash <ip-address> ModSecurity '$NOTES'
  www-security-assistant.bash <ip-address> ModEvasive
  www-security-assistant.bash <ip-address> a2Analyst
  www-security-assistant.bash <ip-address> FloodDetector '$NOTES'
  ````

In this mode the script provides **two action stages** and for every action it will **send an email** to the administrator(s).

* First stage: for the first few **'transgressions'** the source `$IP` will be **banned for a period of time** equal to the value of `$BAN_TIME`. This mode uses the command `at`.

* Second stage: when the number of the transgressions from certain `$IP` becomes equal to the value of `$LIMIT`, this `$IP` address will be **banned permanently** through Iptables and will be added to the `$WWW_SAS_BAN_LIST`.

The script have a kind of integration with [`www.abuseipdb.com`](https://www.abuseipdb.com). It can curl data from their API (further probably will have automatic report feature) to provide it within the emails. If you want to use this feature, you should register on [`www.abuseipdb.com`](https://www.abuseipdb.com) and provide your API key within the configuration file - variable `$AbuseIPDB_APIKEY`.

The script is able to send two kinds of emails, depending on your preferences provided within the configuration file. Is can send HTML formated emails and plain text emails - variables `$EMAIL_TO` and `$EMAIL_TO_PLAIN`. If none of these variables is set, the script execution will be discontinued (interrupted) before the email section.

Here is how one HTML formated email looks like:

![Examples email sent by the script.](.images/www-security-assistant-email-demo.png)

### Manual mode

This mode accept the following options:

* `www-security-assistant.bash <ip-address>` **`--DROP "log notes"`**

    Creates an entry into the file `/etc/www-security-assistant/www-security-assistant.black.list` and generates a rule as:

      iptables -A WWWSAS -s $IP -j DROP

* `www-security-assistant.bash <ip-address>` **`--CLEAR "log notes"`**

    Creates an entry into the file `/etc/www-security-assistant/www-security-assistant.clear.list`, remove the certain Iptables rule, removes the `$IP` from the history and from the `$WWW_SAS_BAN_LIST`:

      iptables -D WWWSAS -s $IP -j DROP

* `www-security-assistant.bash <ip-address>` **`--ACCEPT "log notes"`**

  Creates only an entry into the file `/etc/www-security-assistant/www-security-assistant.white.list`.

* `www-security-assistant.bash <ip-address>` **`--ACCEPT-CHAIN "log notes"`**

  Creates an entry into the file `/etc/www-security-assistant/www-security-assistant.white.list` and generates a rule as:

      iptables -A WWWSAS -s $IP -j ACCEPT

### Dependencies

* All dependencies will checked (and installed) during the SETUP process (explained in the installation section).

* The script uses `iptables-save.sh` and the `iptables` chain `WWWSAS`, explained in the [next section](#iptables--basic-configuration--save-and-restore). It will create and maintain few files within the `$WORK_DIR`, for example:

  * `www-security-assistant.history` - contains the data for the previous IP addresses transgressions.
  * `www-security-assistant.mail` (`.plain`) - the content of the last email sent by the script.
  * `www-security-assistant.white.list`; `www-security-assistant.black.list` and `www-security-assistant.clear.list`.

  There is a plenty of file extensions, that are included in the `.gitignore` file and will be not tracked, they will exist only locally.

* The script needs a minimal configuration to send emails:

  ````bash
  sudo apt install mutt mailutils postfix # s-nail
  sudo dpkg-reconfigure postfix  # For General type: Internet Site
  echo 'Test passed.' | mail -s Test-Email email@example.com
  ````

  If there is any configured HTTPS service, its [TLS certificate can be used within the Postfix service][5]. Also see [this](https://askubuntu.com/a/732782/566421) and [this](https://askubuntu.com/q/1031366/566421) Q&Ahow to use `/.mailrc`.

* `sudo apt install at` - see [`man at`][6].

### Installation

* Create work directory, let's call it `/etc/www-security-assistant`. Download [**`www-security-assistant.bash`**](www-security-assistant.bash) and make it executable:

    ````bash
    sudo mkdir /etc/www-security-assistant
    sudo wget -O /etc/www-security-assistant/www-security-assistant.bash https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/www-security-assistant.bash
    sudo chmod +x /etc/www-security-assistant/www-security-assistant.bash
    ````

* Make **`www-security-assistant`** available as custom command:

      sudo ln -s /etc/www-security-assistant/www-security-assistant.bash /usr/local/bin/www-security-assistant

* Grant permission to `www-data` to run `www-security-assistant.bash` without password via `sudo`. Use the following command to [create and edit safely][18] a new file with an additional '`sudoers`' rule:

      sudo visudo -f /etc/sudoers.d/www-security-assistant

   Add the following line inside the file - save the file and exit:

      www-data ALL=(ALL) NOPASSWD: /etc/www-security-assistant/www-security-assistant.bash

### Configuration file

There is a default configuration file named [**`www-security.assistant.conf.example`**](www-security-assistant.conf.example). You must create your configuration file based on it:

````bash
sudo wget -O /etc/www-security-assistant/www-security.assistant.conf.example https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/www-security.assistant.conf.example
sudo cp /etc/www-security-assistant/www-security.assistant.conf{.example,}
````

* Tweak **`www-security.assistant.conf`**. Change at least the value of the variable `$EMAIL_TO`.

### ~~Installation script - install the entire bundle WWW Security Assistant~~

~~**Of course if you want you can clone the GitHub repository.** I would to do not use `git` to `clone` this repository on my *production* server, because some mistaken usage of `pull`/`push` could cause a problem. So I would prefer to place each file on its place *manually*. The [installation script](www-security-assistant.install.bash) will do that for you. It has two modes - installation and update. You can run this scrip on fly by the command:~~

~~`wget -qO www-security-assistant.install.bash https://.../www-security-assistant.install.bash &&
chmod +x www-security-assistant.install.bash &&
sudo ./www-security-assistant.install.bash`~~

~~**I would prefer to do not use this script the first time when I'm installing and setting up the `www-security-assistant` bundle!** Please Read Forward!~~

### Check-up

* Represent yourself as `$AGENT` and check whether the Automatic MODE works properly:

      www-security-assistant.bash 192.168.1.101 Guardian

  Then check your e-mail, type `iptables -L WWWSAS -n`, review the files `www-security-assistant.history` and `www-security-assistant.mail`. Run the above command 5 times and review the files `www-security-assistant.black.list` and `iptables.current-state.conf`.

* Check whether the Manual MODE works properly - add your localhost to the White List:

      www-security-assistant.bash 127.0.0.1 --ACCEPT "Server's localhost IP"

  Then check the file `www-security-assistant.white.list`.

### References

* [**The source of the main idea of this script**][7] | [Simple Denial of Service][8]
* [send email, the minimal required configuration][4].
* [How do I set Cron to send emails?](https://askubuntu.com/a/1021086/566421)

> **The rest of this tutorial is how to integrate the script with your system.**

## Iptables – Basic Configuration – Save and Restore

### Basic configuration

Please read [this manual][10] before adding the following rules.

````bash
sudo iptables -F

sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Check up:
sudo iptables -S
sudo iptables -L
sudo iptables -L WWWSAS -n

# This rule may lock you out of the system!
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT ACCEPT
````

**Before you do the next actions open a new SSH connection and try to login into your system to check whether everything works fine!**

### Save and Restore

This could be achieved via custom scripts, that will save and restore the `iptables` coning during system's stop-start (or reboot) process. (If we using UFW to setup Iptables rules this step is not needed.)

  ````bash
  printf '#!/bin/sh\n/sbin/iptables-save > /etc/www-security-assistant/iptables.current-state.conf\nexit 0\n' | sudo tee /etc/www-security-assistant/iptables-save.sh
  printf '#!/bin/sh\n/sbin/iptables-restore < /etc/www-security-assistant/iptables.current-state.conf\nexit 0\n' | sudo tee /etc/www-security-assistant/iptables-restore.sh
  sudo chmod +x /etc/www-security-assistant/iptables-restore.sh /etc/www-security-assistant/iptables-save.sh
  ````

  ````bash
  sudo ln -s /etc/www-security-assistant/iptables-save.sh /etc/network/if-post-down.d/iptables-save
  sudo ln -s /etc/www-security-assistant/iptables-restore.sh /etc/network/if-pre-up.d/iptables-restore
  ````

### Create new chain

Create new chain, called `WWWSAS` and insert it as number 3 into the `INPUT` chain:

    sudo iptables -N WWWSAS
    sudo iptables -I INPUT 3 -j WWWSAS

### Check-up (Iptables – Basic Configuration – Save and Restore)

 Reboot the system and check the configuration. Please use `sudo systemctl reboot` (do not use the force option `reboot -f`). When the system is back on line we can check if the newly created chain exists by:

    sudo iptables -L WWWSAS -n

### References (Iptables – Basic Configuration – Save and Restore)

* Iptables How To: [**Help Ubuntu**][9] | [Digital Ocean][10]
* [Why does a valid set of Iptables rules slow my server?][11] | [Iptables status slow?][12]

## ModEvasive for Apache2

> ModEvasive is an evasive maneuvers module for Apache to provide
> evasive action in the event of an HTTP DoS or DDoS attack or brute
> force attack. It is also designed to be a detection tool, and can be
> easily configured to talk to ipchains, firewalls, routers, and
> etcetera. [*Read more...*][13]

### Installation (ModEvasive for Apache2)

* Install and enable the module:

      sudo apt install libapache2-mod-evasive
      sudo a2enmod evasive

* Create Log Directory and make it accessible for `www-data`:

      sudo mkdir -p /var/log/apache2_mod_evasive
      sudo chown www-data /var/log/apache2_mod_evasive

* Adjust the basic configuration – comment out and edit certain directives in the configuration file:

      /etc/apache2/mods-enabled/evasive.conf

* Restart Apache: `sudo systemctl restart apache2.service`.

### Check-up (ModEvasive for Apache2)

* Open a web page from your server and refresh the browser window few times intensively (usually `F5` can be used) - you must get ***403 Forbidden*** error message (that will remains several seconds) and also, into the log directory, will be generated a new lock file. This file should be deleted for further transgressions detection from this IP address.

### References (ModEvasive for Apache2)

* [Matt Brock's Blog: Security hardening on Ubuntu Server 14.04][14]
* [TechMint: Protect Apache Against Brute Force or DDoS Attacks][15]
* [GitHub: Shivaas/mod_evasive][13] | [GitHub: Jzdziarski/mod_evasive][16] | [HeliconTech: mod_evasive][17]

## ModEvasive ► WWWSAS ► Iptables

Here we will configure `mod_evasive` to talk to `iptables` through the `www-security-assistant.bash`, created in the above section.

* Edit **`/etc/apache2/mods-available/evasive.conf`** in this way:

  ````apache
  <IfModule mod_evasive20.c>
      DOSHashTableSize    3097
      DOSPageCount        9
      DOSSiteCount        70
      DOSPageInterval     2
      DOSSiteInterval     2
      DOSBlockingPeriod   10

      #DOSEmailNotify     your@email.foo
      DOSLogDir           "/var/log/apache2_mod_evasive"
      DOSSystemCommand    "sudo /etc/www-security-assistant/www-security-assistant.bash %s 'ModEvasive' 'AutoMode' >> /etc/www-security-assistant/www-security-assistant.exec.log 2>&1"
  </IfModule>
  ````

* Create log file and Restart the Apache server:

  ````bash
  sudo touch /etc/www-security-assistant/www-security-assistant.exec.log && sudo chown www-data /etc/www-security-assistant/www-security-assistant.exec.log
  sudo systemctl restart apache2.service
  ````

To test this configuration we can simulate DDOS attack via the `F5` method, mentioned above, or we can use a commands as [`ab`][19], [`hping3`][20], etc.

**Attention:** Be careful because the rule `iptables -A INPUT -s $BAD_IP -j DROP`, used in the script, will DROP all **new** connections from the source `$IP`, including the SSH connections. It is good to have a backup way to connect to the server during the tests. Or you can change this rule to work only with the HTTP/HTTPS ports.

## ModSecurity 2.9 for Apache2

> [ModSecurity][21] is a web application firewall engine that provides very
> little protection on its own. In order to become useful, ModSecurity
> must be configured with rules. In order to enable users to take full
> advantage of ModSecurity out of the box, Trustwave's Spider Labs is
> providing a free certified rule set for ModSecurity™ Core Rules
> provide generic protection. [*Read more...*][22]

* Please note [ModSecurity 3.0](https://github.com/SpiderLabs/ModSecurity/releases/tag/v3.0.0) is already available, but it is not included yet in the official Ubuntu repositories.

### Installation (ModSecurity 2.9 for Apache2)

* Install and enable the module:

      sudo apt install libapache2-mod-security2 --no-install-recommends
      sudo a2enmod security2

 We are using `--no-install-recommends` because otherwise `modsecurity-crs` will be installed (check by: `apt show libapache2-mod-security2`), but the version from the repository usually is outdated than the master's branch in GitHub, that we will use later here.

* Create configuration file:

  ````bash
  sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  ````

  Read and edit `/etc/modsecurity/modsecurity.conf` carefully! Add or change at least the following directives:

  ````apache
  # -- Rule engine initialization ----------------------------------------------
  SecRuleEngine On

  # -- Debug log configuration -------------------------------------------------
  SecDebugLogLevel 2
  SecDebugLog "/var/log/apache2_mod_security/modsec_debug.log"

  # -- Audit log configuration -------------------------------------------------
  SecAuditLog "/var/log/apache2_mod_security/modsec_audit.log"

  # -- Guardian log configuration -------------------------------------------------
  SecGuardianLog /var/log/apache2_mod_security/modsec_guardian.log
  # This will be piped to an external script:
  #SecGuardianLog "|/etc/www-security-assistant/www-security-apache-log-analyst.bash"
  ````

* The file `/etc/apache2/mods-enabled/security2.conf` involves `/etc/modsecurity/modsecurity.conf` into Apache's configuration. At this stage `security2.conf` shall look as this:

  ````apache
  <IfModule security2_module>
      SecDataDir /var/cache/modsecurity
      IncludeOptional /etc/modsecurity/*.conf
  </IfModule>
  ````

* Create Log Directory:

      sudo mkdir -p /var/log/apache2_mod_security

* Setup log rotation. First create config file:

      sudo cp /etc/logrotate.d/apache2 /etc/logrotate.d/apache2-modsec

  Then edit the new file in this way:

      /var/log/apache2_mod_security/*.log { … }

* Restart Apache: `sudo systemctl restart apache2.service`.

* To force the `logrotate` use the command: `sudo logrotate --force /etc/logrotate.d/apache2-modsec`

### Check-up (ModSecurity 2.9 for Apache2)

* if you enabled the base rules, try to access ([source](https://gist.github.com/davidrios/424583df2ac768675330)):

  ````apache
  http://<YOUR_HOST>/?param='; drop database test; --
  ````

  You should see entries in /var/log/apache2/error.log and /var/log/apache2/modsec_audit.log.

* Create an additional configuration file in `/etc/modsecurity`, call it for example `z-customrules.conf`, and add the following rule as its content:

  ````apache
  # Directory traversal attacks
  SecRule REQUEST_URI "../" "t:urlDecodeUni, deny, log, id:109"
  ````

  Restart the server: `sudo systemctl restart apache2.service`. Open your browser and type `https://example.com/?abc=../`. The result will be: ***403 Forbidden***. Check the log files in `/var/log/apache2_mod_security` for more details.

* To make the things more *fun* place the script [`www-security-assistant-issues.php`](https://github.com/pa4080/www-security-assistant/blob/stable.v.2/appendix/var/www/html/www-security-assistant-issues.php) in an appropriate location within your `DocumentRoot` (here I'm assuming this place is `/var/www/html`):

      sudo wget -O /var/www/html/www-security-assistant-issues.php https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/appendix/var/www/html/www-security-assistant-issues.php

  Then modify the above rule in the following way:

  ````apache
  # Directory traversal attacks with redirection (or use URL instead of URI: redirect:'https://example.com/www-security-assistant-issues.php')
  SecRule REQUEST_URI "../" "t:urlDecodeUni, deny, log, id:109, redirect:'/www-security-assistant-issues.php'"
  ````

  Restart the server, then open your browser and type `https://example.com/?abc=../` ;-) The idea is borrowed from the SE's script [`BotLovin.cs`](https://gist.github.com/NickCraver/c9458f2e007e9df2bdf03f8a02af1d13).

* Edit `/etc/modsecurity/z-customrules.conf` once again and comment (disable) the rule * this was just test example and it is covered by OWASP CRS, described in the next section.

* Here is another example where we will redirect all `wp-admin` page requests, but except these from certain IP addresses (note the `chain`):

  ````apache
  # Block wp-admin access
  SecRule REQUEST_URI "^/wp-admin" "id:108, log, deny, status:403, t:lowercase, chain, redirect:'/www-security-assistant-issues.php'"
      SecRule REMOTE_ADDR "!@ipMatch 192.168.1.11,99.77.66.12"
  ````

  Here we have two disruptive actions: (1) `deny, status:403` and (2) `redirect:'/www-security-assistant-issues.php'`. Actually we do not need of the `deny` action because it will be override by the `redirect` action.

### References (ModSecurity 2.9 for Apache2)

* [**Processing phases of Modsecurity**][71]
* [ModSecurity HandBook by Ivan Ristic][25]
* [**ModSecurity 2.5** by Mischel Magnus][26]
* [10 ways to improve your protection with ModSecurity][27]
* SpiderLabs/ModSecurity on GitHub: [**Reference Manual**][23] and [FAQ][24]
* HTBridge: [Patching Complex Web Vulnerabilities Using ModSec][28] | [Path Traversal][29]
* [TechMint: Protect Apache Against Brute Force or DDoS Attacks Using ModSec][30]
* [OWASP Wiki: **Testing for SQL Injection**][70]

## ModSecurity OWASP Core Rule Set 3.x

In Ubuntu 16.04 you can install CSR by the command `apt install modsecurity-crs` (more details about this approach can be fund in [this manual][31]), but the version from the repository usually is outdated than the master's branch in GitHub. So here we will install [**CSR 3.x**][32] from the master branch in GitHub (detailed instructions are provided within the [Installation manual][33]) ([Git][34] is required). So before begin please remove the Ubuntu's repository version ov `modsecurity-crs`:

````bash
sudo apt purge modsecurity-crs
````

### Installation (ModSecurity OWASP Core Rule Set 3.x)

* Clone CSR into the directory `/etc/modsecurity/modsecurity-crs` and update the GeoIP data base:

      sudo git clone https://github.com/SpiderLabs/owasp-modsecurity-crs /etc/modsecurity/modsecurity-crs
      sudo /etc/modsecurity/modsecurity-crs/util/upgrade.py --geoip --crs

* Upgrade and auto renew the GeoIP database. (The GeoIP DB is no longer included with the CRS. Instead you are advised to download it regularly.) The script `util/upgrade.py` brings this functionality. You can use it as follows in cron - `sudo crontab -e`:

  ````cron
  0 2 * * * /etc/modsecurity/modsecurity-crs/util/upgrade.py --geoip --crs --cron >> /var/log/apache2_mod_security/owasp-crs-upgrade.log 2>&1
  ````

* Create configuration files:

      sudo cp /etc/modsecurity/modsecurity-crs/crs-setup.conf{.example,}
      sudo cp /etc/modsecurity/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf{.example,}
      sudo cp /etc/modsecurity/modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf{.example,}

  **Read and edit these files carefully!** Comment out at least [`SecGeoLookupDB`][35] directive:

      SecGeoLookupDB util/geo-location/GeoIP.dat

* Apply the Apache's configuration. Edit `/etc/apache2/mods-available/security2.conf` in this way:

  ````apache
  <IfModule security2_module>
      SecDataDir /var/cache/modsecurity
      IncludeOptional /etc/modsecurity/*.conf
      IncludeOptional /etc/modsecurity/modsecurity-crs/crs-setup.conf
      IncludeOptional /etc/modsecurity/modsecurity-crs/rules/*.conf
  </IfModule>
  ````

  Save the file and then restart Apache: `sudo systemctl restart apache2.service`.

## ModSecurity Rules Whitelisting

Whitelisting of ModSecurity Rules could be done via the following ModSec directives, that can be used system wide or within virtual host's configuration, also globally, for specific directories or location matches:

  ````apache
  SecRuleRemoveById
  SecRuleRemoveByMsg
  SecRuleRemoveByTag
  SecRuleUpdateTargetById
  SecRuleUpdateTargetByMsg
  SecRuleUpdateTargetByTag
  SecRuleUpdateActionById
  ````

Disable `mod_security2` for phpMyAdmin. Change `/etc/phpmyadmin/apache.conf` in this way:

````apache
<Directory /usr/share/phpmyadmin>
    <IfModule security2_module>
        SecRuleEngine Off
    </IfModule>
</Directory>
````

Disable specific rules for certain directory:

````apache
<Directory /var/www/html>
    <IfModule security2_module>
        SecRuleRemoveById 973301
    </IfModule>
</Directory>
````

Disable rules globally. For this purpose we must add our directives somewhere in Apache's configuration files: `/etc/modsecurity/z-customrules.conf` is a good place.

* Disable rules within the entire Apache's configuration:

  ````apache
  SecRuleRemoveById 973301 950907
  ````

* Whitelist an IP address so it can pass through ModSecurity:

  ````apache
  SecRule REMOTE_ADDR "@ipMatch 192.168.110.1" "phase:1,nolog,allow,ctl:ruleEngine=Off,ctl:auditEngine=Off"
  ````

* Disable rules within Directory match:

  ````apache
  <Directory /var/www/mediawiki/core>
      SecRuleRemoveById 973301 950907
  </Directory>
  ````

* **Update rule's action by its ID** within Location match:

  ````apache
  <LocationMatch "/index.php.*">
      SecRuleUpdateActionById 973301 "pass"
      SecRuleUpdateActionById 950907 "pass"
  </LocationMatch>
  ````

 In the above examples we assume that `973301` and `950907` are rule IDs that obstruct the normal work of our web apps. We can find rules as these by an analyze of the file **`modsec_audit.log`**, where at the bottom we will find entries that cantons strings as: `[id "973301"]` and `[id "950907"]`:

    cat /var/log/apache2/mod_security2/modsec_audit.log | grep -Ewo 'id \"[0-9]{1,10}' | sed 's/id \"//' | sort -r | uniq

### References (ModSecurity Rules Whitelisting)

* [**Sam Hobbs: Example Whitelisting Rules for Apache ModSec and the OWASP CRS**][36]
* [SpiderLabs Blog: ModSec Advanced: Exception Handling][37]
* [NetNea: Handling False Positives with the OWASP ModSec CRS][38]
* [NetNea: Including OWASP ModSec CRS][39]

## ModSecurity Rules ► WWWSAS ► Iptables

Here are given few more examples how to create custom SecRules, also how we can call WWW Security Assistant Script (WWWSAS) through them.

### Initial Setup

We need of an additional startup scrip - [`modsecurity-assistant.bash`][40]. The reason is that, ModSecurity's `exec` action has too simple and limited syntax.

````bash
sudo wget -O /etc/www-security-assistant/modsecurity-assistant.bash https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/modsecurity-assistant.bash
sudo chmod +x /etc/www-security-assistant/modsecurity-assistant.bash
````

If you look inside the script you will see few variables that are exported by ModSecurity. These are: `$REQUEST_URI`, `$ARGS`, `$SERVER_NAME`, `$REMOTE_ADDR`, `$REMOTE_HOST` and `$UNIQUE_ID`. The other variables are explained inside the script.

### Create custom rule and call our scripts through it

First let's create a rule that will execute `modsecurity-assistant.bash` (and call `www-security-assistant.bash`) when the request URI contains a word that is included in our blacklist. Open `/etc/modsecurity/z-customrules.conf` and add the following lines to the bottom:

````apache
# REQUEST_URI words blacklist
#
SecRule REQUEST_URI "@pmFromFile /etc/www-security-assistant/modsecurity-uri.black.list" \
    "id:150, log, t:lowercase, chain, \
     drop, deny, status:403, redirect:'/www-security-assistant-issues.php'"
     SecRule REMOTE_ADDR "!@ipMatchFromFile /etc/www-security-assistant/modsecurity-ip.white.list" \
        "setenv:REMOTE_HOST=%{REMOTE_HOST}, \
         setenv:ARGS=%{ARGS}, \
         exec:/etc/www-security-assistant/modsecurity-assistant.bash"
````

* `REQUEST_URI` - this variable contains the full URI from the current request. The rule could be more wide: `SecRule REQUEST_URI|ARGS|REQUEST_BODY ...`

* `@pmFromFile` will read the file `modsecurity-uri.black.list` that contains list of phrases, where each specific phrase or word is placed into a new line. You can collect interesting words and phrases from the log files. If there is a *particular* match between `REQUEST_URI` and our list of patterns the rule will be applied. The file could be empty, but you must create (`touch`) it.

* The `log` action will create log entries in the log files for this rule with `id:150`.

* `drop`, `deny` (with `status`) and `redirect` actions belong to the *disruptive* group of actions, they must be in the beginning of the rule `chain` (if there is a chain). The second action will override the first one and the third will override the second, so you must choice which you want to be performed and can delete the others.

* `chain` action will call the next rule of of the chain, note that second rule, doesn't have `id`.

* `REMOTE_ADDR` contains the IP address of the request.

* `@ipMatchFromFile` will the file `modsecurity-ip.white.list` that contains white-list of IP addresses, separated at new lines. CIDR  entries are also acceptable. Because the *disruptive* action is always located in the leading rule of the chain it will be applied, but when certain IP is in this white list the `exec` action will not be applied. The file could be empty, but you must create (`touch`) it.

* `exec` action will call our external script. This action isn't *disruptive* and will be executed when the current rule return true. **When this action is applies the remote IP will be processed through our scripts.**

* `setenv` this action will export certain [internal variables][41] `=%{...}` as envvars, exported names can be different from the internals. Some variables must be exported manually, some other are exported automatically - probably it is a small bug (in some cases the manual export with the same names, for example `setenv:REQUEST_URI=%{REQUEST_URI}`, will cause a blank value of the exported variable).

### Check-up (Create custom rule and call our scripts)

Let's assume you do not have Joomla on your server, edit the file `modsecurity-uri.black.list` and add a line with content `/joomla`. Then type in your browser `https://exemple.com/joomla`. You should be redirected and blocked through Iptables. Clear the records `sudo www-security-assistant.bash <your-ip> --CLEAR 'some note'`, add your IP in `modsecurity-ip.white.list` and do the exercise again. Now you should be redirected, but not blocked.

### Connect our scripts with OWASP Core Rule Set 3.x

To do that we will update the default action of the **Anomaly Mode Rules** (949110 and 959100). For this purpose edit the file  `/etc/modsecurity/modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf` and add the next lines to the bottom:

````apache
# -- Anomaly Mode - Update actions by ID -----
#

SecRuleUpdateActionById 949110 "t:none, drop, deny, status:403, redirect:'/www-security-assistant-issues.php', \
     setenv:REMOTE_HOST=%{REMOTE_HOST}, setenv:ARGS=%{ARGS}, \
     exec:/etc/www-security-assistant/modsecurity-assistant.bash"

SecRuleUpdateActionById 959100 "t:none, drop, deny, status:403, redirect:'/www-security-assistant-issues.php', \
     setenv:REMOTE_HOST=%{REMOTE_HOST}, setenv:ARGS=%{ARGS}, \
     exec:/etc/www-security-assistant/modsecurity-assistant.bash"

# -- Anomaly Mode - Whitelist some URI and IP addresses -----
#    Unfortunately @pmFromFile doesn't work here;
#    The regexp below is a working example, that will whitelist some WordPress and MediaWiki actions.
#

SecRule REQUEST_URI "^/wp-admin/admin-ajax.php*|^/index\.php\?title=.*&action=(submit|raw&ctype=text/javascript|raw&ctype=text/css)$" \
    "id:'999010', t:none, phase:1, pass, \
     ctl:ruleRemoveById=949110, \
     ctl:ruleRemoveById=959100"

SecRule REMOTE_ADDR "@ipMatchFromFile /etc/www-security-assistant/modsecurity-ip.white.list" \
    "id:'999020', t:none, phase:1, pass, \
     ctl:ruleRemoveById=949110, \
     ctl:ruleRemoveById=959100"
````

### Check-up (Connect our scripts with OWASP Core Rule Set 3.x)

Don't forget to restart (or reload) Apache to apply the configuration changes. Don't forget to clear the records periodically during the tests, otherwise you can be blocked permanently :-)

Simulate directory traversal attack:

````bash
https://example.com/?abc=../../../                         # This should be redirected and blocked
https://example.com/wp-admin/admin-ajax.php?abc=../../../  # This should pass because of the whitelist rule
````

Simulate [SQL Injection][70] attack:

````bash
https://example.com/index.php?username=1'%20or%20'1'%20=%20'1&password=1'%20or%20'1'%20=%20'1
https://example.com/?username=1'%20or%20'1'%20=%20'1&password=1'%20or%20'1'%20=%20'1
https://example.com/index.php?username=1'%20or%20'1'%20=%20'1'))/*&password=foo
````

### References (ModSecurity Rules ► WWWSAS ► Iptables)

* [**Executing shell scripts p.58**][26] | [Using Lua scripts with ModSec][42]
* Examples: [Block IP][43] | [GeoIP][44] | [Multiple 404s][45] | [Block string][46] | [Redirection][47] | [`exec` on `severity` level][48]

## WWWSAS Whitelist Rule Generator ► ModSecurity Rules Whitelisting

The tool [**`modsecurity-whitelist-rule-generator.bash`**](modsecurity-whitelist-rule-generator.bash) is able to parse the ModSecurity's audit log file (`modsec_audit.log`) and *generate whitelisting rules*, based on the `REQUEST_URI`. The necessary configuration data must be provided within `www-security-assistant.conf`. The common call syntax is:

````bash
modsecurity-white-list-rule-generator '999xxx' ['latest-log' | 'unique-id' '27-CharactersLong-UniqueID']
````

Where `999xxx` is the id of the new rule that will be generated. When the provided value is **`999999`** the script will parse and calculate the id number automatically, based on the values of `$MOD_SECURITY_WHITELIST_FILE` and `$SECURITY_RULE_PARSE_METHOD` from the configuration file.

The script has two modes:

* **`latest-log`** - in this mode the script will parse the last thread from the audit log (provided by the value of `$MOD_SECURITY_AUDIT_LOG` within the configuration file). This is the default mode, when the script is called without arguments (or only with the first one).

* **`unique-id`** - in this mode the script will parse the thread, from the audit log file, by its Unique ID. This is the powerful and useful mode.

 Within the email sent by the main scrip (`www-security-assistant`) you will receive nice prepared command for the current thread, that will look as:

 ````bash
sudo modsecurity-whitelist-rule-generator '999999' 'unique-id' 'W7d0wZeJo61rdV@mr9@S1AAA'
 ````

### Installation (modsecurity-whitelist-rule-generator)

* Download [**`modsecurity-whitelist-rule-generator.bash`**](/modsecurity-whitelist-rule-generator.bash) and make it executable:

    ````bash
    sudo wget -O /etc/www-security-assistant/modsecurity-whitelist-rule-generator.bash https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/modsecurity-whitelist-rule-generator.bash
    sudo chmod +x /etc/www-security-assistant/modsecurity-whitelist-rule-generator.bash
    ````

* Make **`modsecurity-whitelist-rule-generator`** available as custom command:

      sudo ln -s /etc/www-security-assistant/modsecurity-whitelist-rule-generator.bash /usr/local/bin/modsecurity-whitelist-rule-generator

## ModSecurity and Apache Log Files

> The Apache web server can be configured to give the server
> administrator important information about how it is functioning...
> The main avenue for providing feedback to the administrator is through
> the use of log files. [*Read more...*][49]

**ModSecurity** has powerful [logging mechanism][50]. By the directive [**`SecGuardianLog`**][51] it provides a log feed specially designed to work with external scripts.

> Currently the only tool known to work with *guardian logging* is
> **`httpd-guardian`**, which is part of the [Apache httpd tools
> project][53]. The `httpd-guardian` tool is designed to defend against
> denial of service attacks. It uses the `blacklist tool` to
> interact with an iptables-based... firewall, dynamically blacklisting
> the offending IP addresses. [*Read more...*][51]

### References (ModSecurity and Apache Log Files)

* Apache 2.4: [Log Files][54] | [mod_log_config][55] | [ErrorLog Directive][56]
* [SudleyPlace: Apache Server Piped Error Logs][57]
* [The Art Of WEB: System: Analyzing Apache Log Files][58]

## ModSecurity Log Files ► Fail2Ban ► Iptables

It is possible to setup Fail2Ban for data parsing of Apache's log files. `modsec_audit.log` is probably the best choice, but see also the sections where we talk about of `SecGuardianLog`.

[Take care][59] that `SecAuditLogRelevantStatus` in `/etc/modsecurity/modsecurity.conf` is commented. Otherwise everyone that receives a 404 error page would be blocked by fail2ban.

  ````apache
  SecAuditEngine RelevantOnly
  #SecAuditLogRelevantStatus "^(?:5|4(?!04))"
  ````

Currently Fail2Ban is not implemented in any way in this project.

### References (ModSecurity Log Files ► Fail2Ban ► Iptables)

* Fail2Ban Wiki: [Apache][60] | [HOWTO fail2ban with ModSecurity2.5][59]
* [The Rietta Blog][61] | [OcpSoft][62] | [ModSec IP Tables][63]

## ModSecGuardianLog ► HTTPD-Guardian ► WWWSAS ► Iptables

> [`httpd-guardian`][52] - detect DoS attacks by monitoring requests
> Apache Security, Copyright (C) 2005 Ivan Ristic - is designed to
> monitor all web server requests through the piped logging mechanism.
> It keeps track of the number of requests sent from each IP address...
> httpd-guardian can either emit a warning or execute a script to block
> the IP address...
>
> This script can be used with [Apache2 logging mechanism][54], or with
> [ModSecurity][51] (better).

### Installation and Setup within the Current Circumstances

Download [`httpd-guardian`][52] and make it executable:

````bash
sudo wget -O /etc/www-security-assistant/httpd-guardian.pl https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/httpd-guardian.pl
sudo chmod +x /etc/www-security-assistant/httpd-guardian.pl
````

Modify the following variables to call our WWWSAS script (note this is already made in this redistributed version):

````perl
my $PROTECT_EXEC = "exec /etc/www-security-assistant/www-security-assistant.bash %s 'Guardian' 'AutoMode' >> /etc/www-security-assistant/www-security-assistant.exec.log 2>&1";
my $THRESHOLD_1MIN = 3; # 120 requests in a minute
my $THRESHOLD_5MIN = 2; # 360 requests in 5 minutes
my $COPY_LOG = "/var/log/apache2_mod_security/modsec_guardian.httpdguardian.log";
my $SAVE_STATE_FILE = "/etc/www-security-assistant/httpd-guardian.state";
````

Apply the following change within Apache's configuration (`/etc/modsecurity/modsecurity.conf`), then restart it:

````apache
#SecGuardianLog /var/log/apache2_mod_security/modsec_guardian.log
SecGuardianLog "|/etc/www-security-assistant/httpd-guardian.pl"
````

### Check-up (odSecGuardianLog ► HTTPD-Guardian ► WWWSAS ► Iptables)

To test the script disable ModEvasive (`sudo a2dismod evasive` don't forget to enable it later) and restart Apache. Then `tail` the exec log:

````bash
tail -F /etc/www-security-assistant/www-security-assistant.exec.log
````

And from another instance perform DoS attack, for example use `ab` in this way:

````bash
for i in {1..20}; do (ab -n 200 -c 10 https://example.com/ &); done
````

## ModSecGuardianLog ► HTTPD Custom Analyze ► WWWSAS ► Iptables

Here is presented a simple script, called [**`httpd-custom-analyze.bash`**][64], that isn't something special but could be a nice example. Its features are described within the script's body.

### Installation and Setup

Download [`httpd-custom-analyze.bash`](httpd-custom-analyze.bash) and make it executable:

````bash
sudo wget -O /etc/www-security-assistant/httpd-custom-analyze.bash https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/httpd-custom-analyze.bash
sudo chmod +x /etc/www-security-assistant/httpd-custom-analyze.bash
````

Apply the following change within Apache's configuration (`/etc/modsecurity/modsecurity.conf`), then restart it:

````apache
#SecGuardianLog /var/log/apache2_mod_security/modsec_guardian.log
#SecGuardianLog "|/etc/www-security-assistant/httpd-guardian.pl"
SecGuardianLog "|/etc/www-security-assistant/httpd-custom-analyze.bash"
````

* The script will call `www-security-assistant.bash` when the threshold is reached.

* The script can pipe the `SecGuardianLog` also to `httpd-guardian.pl` so both will work simultaneously. Currently ths option is disabled - see line 35.

* Within the current configuration to get both `httpd-` scripts to work simultaneously edit `/etc/modsecurity/modsecurity.conf` and pipe `SecGuardianLog` to both.

* To perform a test follow the tips from the above section.

## WWWSAS Flood Detector ► WWWSAS ► Iptables

The script [**`flood-detector.bash`**](flood-detector.bash) is designed to analyse the output of 'netstat -tnupa' for *threshold number* of 'SYN_RECV' (or any other) TCP states per IP/PORT, etc. When a possible flood attack is detected it calls the main script from the same bundle - `www-security-assistant.bash`. The script is designed to be run via `crontab` as well as shell command.

We can call the script from the command line by any of the following commands. This is the default mode, when the script is called without arguments. In this mode it will output the result of the analyse in the CLI. Call syntax:

````bash
/etc/www-security-assistant/flood-detector.bash
flood-detector
````

The automatic mode should be used when the script is called from `crontab` (`sudo crontab -e`). In this mode when a possible flood attack is detected the script will execute `www-security-assistant.bash`. For this mode we must provide `AutoMode` as value of the first positional parameter:

````bash
* * * * * "/etc/www-security-assistant/flood-detector.bash" 'AutoMode' >> "/etc/www-security-assistant/www-security-assistant.exec.log" 2>&1
````

### Installation (flood-detector)

* Download [**`flood-detector.bash`**](flood-detector.bash) and make it executable:

    ````bash
    sudo wget -O /etc/www-security-assistant/flood-detector.bash https://raw.githubusercontent.com/pa4080/www-security-assistant/stable.v.2/flood-detector.bash
    sudo chmod +x /etc/www-security-assistant/flood-detector.bash
    ````

* Make **`flood-detector`** available as custom command:

    ````bash
    sudo ln -s /etc/www-security-assistant/flood-detector.bash /usr/local/bin/flood-detector
    ````

### Check-up (flood-detector)

Before setup your Iptables anti flood rules and kernel parameters you can perform simple syn flood attack from another machine and then run `sudo flood-detector` (and if you want `sudo netstat -tnupa | grep 'SYN_RECV'`) from the CLI to check the result. To simulate such attack you can use `hping3`, for example:

````bash
sudo hping3 -S 192.168.100.100 -p 443 --flood
````

### Notes

We can prevent most of the flood attacks by proper settings of the kernel parameters (`/etc/sysctl.conf`), when this is possible, or by well defined `iptables` rules. But sometimes not every transgression is caught, in these cases a script like those presented here could be helpful. The average sys time of the idle execution of `flood-detector.bash` is about 0.015s (on no so powerful system). Here are few references according to this topic:

* [**DDoS Protection With IPtables: The Ultimate Guide**](https://javapipe.com/ddos/blog/iptables-ddos-protection/)
* [**How to protect from port scanning and smurf attack in Linux Server by iptables**](http://sharadchhetri.com/2013/06/15/how-to-protect-from-port-scanning-and-smurf-attack-in-linux-server-by-iptables/)
* [**Monitor TCP SYN Flooding Attacks**](http://www.uberobert.com/nagios-check-for-tcp-syn-flooding-attacks/) (Similar script written on Ruby.)
* [**I am under DDoS. What can I do?**](https://serverfault.com/questions/531941/i-am-under-ddos-what-can-i-do) (ServerFault Q&A Canonical Question.)
* [How to verify DDOS attack with netstat command?](https://www.supportpro.com/blog/how-to-verify-ddos-attack-with-netstat-command/)
* [How to verify DDOS attack with netstat command on Linux Terminal.](https://linuxaria.com/howto/how-to-verify-ddos-attack-with-netstat-command-on-linux-terminal)
* [DDOS Attack detection with netstat](https://serverfault.com/questions/403695/ddos-attack-detection-with-netstat) (ServerFault Q&A)
* [10 iptables rules to help secure your Linux box](https://www.techrepublic.com/blog/10-things/10-iptables-rules-to-help-secure-your-linux-box/)
* [**SYN Flood Attacks - How to protect?**](https://hakin9.org/syn-flood-attacks-how-to-protect-article/)
* [State NEW packets but no SYN bit set](https://www.linuxtopia.org/Linux_Firewall_iptables/x6193.html)
* [TCP states](https://benohead.com/tcp-about-fin_wait_2-time_wait-and-close_wait/)

## HTTPS and Common Apache Security Tips

> HTTPS is a communications protocol for secure communication over a
> computer network which is widely used on the Internet. HTTPS consists
> of communication over HTTP within a connection encrypted by TLS, or its
> predecessor SSL. [*Read more...*][65]

* First enable SSL module if it is not enabled: `sudo a2enmod ssl`.

* Open port 443 (HTTPS) into the [**firewall**][66].

* Follow [**this manual**][67] and enable a free certificate from Let's Encrypt.

* Check [**this answer**][68] and disable Weak Ciphers.

* Then you can [**force all users to use HTTPS**][69].

See also:

* [Common Apache's Security Tips][1]

  [1]: https://httpd.apache.org/docs/2.4/misc/security_tips.html
  [2]: https://github.com/pa4080/www-security-assistant/blob/stable.v.2/www-security-assistant.bash
  [3]: https://stackoverflow.com/a/39248018/6543935
  [4]: https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-postfix-on-ubuntu-16-04
  [5]: https://help.ubuntu.com/lts/serverguide/postfix.html
  [6]: http://manpages.ubuntu.com/manpages/xenial/man1/at.1posix.html
  [7]: https://serverfault.com/a/588334/364207
  [8]: https://flodesign.co.uk/blog/simple-dos-mitigation-using-mod-evasive/
  [9]: https://help.ubuntu.com/community/IptablesHowTo
  [10]: https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-iptables-on-ubuntu-14-04
  [11]: https://serverfault.com/q/416537/364207
  [12]: http://forums.fedoraforum.org/archive/index.php/t-170914.html
  [13]: https://github.com/shivaas/mod_evasive
  [14]: https://blog.mattbrock.co.uk/hardening-the-security-on-ubuntu-server-14-04/
  [15]: https://www.tecmint.com/protect-apache-using-mod_security-and-mod_evasive-on-rhel-centos-fedora/3/
  [16]: https://github.com/jzdziarski/mod_evasive
  [17]: http://www.helicontech.com/ape/doc/mod_evasive.htm
  [18]: https://askubuntu.com/a/159009/566421
  [19]: https://www.howtoforge.com/benchmark-apache2-vs-lighttpd-static-html-files-p2
  [20]: http://www.binarytides.com/tcp-syn-flood-dos-attack-with-hping/
  [21]: https://modsecurity.org/about.html
  [22]: https://github.com/SpiderLabs/ModSecurity
  [23]: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual
  [24]: https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Frequently-Asked-Questions-(FAQ)
  [25]: http://index-of.es/Networking/MOD%20SECURITY%20handbook.pdf
  [26]: https://github.com/xia0pin9/useful-ebooks/blob/master/ModSecurity%202.5.pdf
  [27]: https://www.purehacking.com/files/resources/ModSecurity_JZ_10ways.pdf
  [28]: https://www.htbridge.com/blog/patching-complex-web-vulnerabilities-using-modsecurity-waf.html#path_traversal
  [29]: https://www.htbridge.com/vulnerability/path-traversal.html
  [30]: https://www.tecmint.com/protect-apache-using-mod_security-and-mod_evasive-on-rhel-centos-fedora/2/
  [31]: https://drive.google.com/file/d/0BwLFsHKU3abkVGJDOUpWSDFSZ1U/view
  [32]: http://modsecurity.org/rules.html
  [33]: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0/master/INSTALL
  [34]: https://help.ubuntu.com/lts/serverguide/git.html
  [35]: http://blog.modsecurity.org/2010/10/detecting-malice-with-modsecurity-geolocation-data.html
  [36]: https://samhobbs.co.uk/2015/09/example-whitelisting-rules-apache-modsecurity-and-owasp-core-rule-set
  [37]: https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--(Updated)-Exception-Handling/
  [38]: https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/
  [39]: https://www.netnea.com/cms/apache-tutorial-7_including-modsecurity-core-rules/
  [40]: https://github.com/pa4080/www-security-assistant/blob/master/modsecurity-assistant.bash
  [41]: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Variables
  [42]: https://gryzli.info/2015/12/25/modsecurity-using-lua-scripts-with-secrulescript/
  [43]: https://www.codeproject.com/Articles/574935/BlockplusIPplususingplusModSecurity
  [44]: https://sourceforge.net/p/mod-security/mailman/message/23655154/
  [45]: https://stackoverflow.com/q/39560772/6543935
  [46]: https://serverfault.com/q/416358/364207
  [47]: https://blog.inliniac.net/2006/08/09/mod_security-redirection/
  [48]: https://stackoverflow.com/q/9355767/6543935
  [49]: https://www.digitalocean.com/community/tutorials/how-to-configure-logging-and-log-rotation-in-apache-on-an-ubuntu-vps
  [50]: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecAuditEngine
  [51]: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secguardianlog
  [52]: https://github.com/pa4080/www-security-assistant/blob/master/httpd-guardian.pl
  [53]: http://apache-tools.cvs.sourceforge.net/viewvc/apache-tools/apache-tools/
  [54]: https://httpd.apache.org/docs/2.4/logs.html
  [55]: http://httpd.apache.org/docs/current/mod/mod_log_config.html
  [56]: https://httpd.apache.org/docs/2.4/mod/core.html#errorlog
  [57]: http://www.sudleyplace.com/pipederrorlogs.html
  [58]: http://www.the-art-of-web.com/system/logs/
  [59]: http://www.fail2ban.org/wiki/index.php/HOWTO_fail2ban_with_ModSecurity2.5
  [60]: http://www.fail2ban.org/wiki/index.php/Apache
  [61]: https://rietta.com/blog/2014/05/27/mod-security-and-fail2ban-as-an-intrusion-prevention-system/
  [62]: http://www.ocpsoft.org/opensource/antispam-filter-with-modsecurity-and-fail2ban/
  [63]: https://serverfault.com/a/628460/364207
  [64]: https://github.com/pa4080/www-security-assistant/blob/master/httpd-custom-analyze.bash
  [65]: https://en.wikipedia.org/wiki/HTTPS
  [66]: https://help.ubuntu.com/lts/serverguide/firewall.html
  [67]: https://askubuntu.com/a/900433/566421
  [68]: https://askubuntu.com/a/903375/566421
  [69]: https://askubuntu.com/a/873876/566421
  [70]: https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)
  [71]: https://malware.expert/modsecurity/processing-phases-modsecurity/

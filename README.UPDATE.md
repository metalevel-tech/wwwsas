# Update log

## ToDo:

* Add check for websearch bots - example for Googe bots (source: [Verifying Googlebot](https://support.google.com/webmasters/answer/80553)):

 ````bash
 $ host 66.249.66.53
 53.66.249.66.in-addr.arpa domain name pointer crawl-66-249-66-53.googlebot.com.
 ````

## Features, presented in the master branch, not presented in the [stable.v.5][8] branch

* Updated logic in the main script according to the PostAnalyse agent - see [**`post-analyse.bash`**](post-analyse.bash).

## Features, presented in [stable.v.5][8], not presented in the [stable.v.4][6] branch

* The script [**`post-analyse.bash`**](post-analyse.bash) is engaged. Also there is a relevant `crontab` script, that will be deployed by the [`SETUP`](SETUP) process - see [`file-system/etc/cron.d/wwwsas-post-analyse`](file-system/etc/cron.d/wwwsas-post-analyse.example).

## Features, presented in [stable.v.4][6], not presented in the [stable.v.3][5] branch

* Full integration with [`www.abuseipdb.com`](https://www.abuseipdb.com) [API V2](https://docs.abuseipdb.com/).

* OWASP ModSecurity CRS - [`v3.2/dev`](https://github.com/SpiderLabs/owasp-modsecurity-crs) integration: the missing `update.py` were copied from the [`v3.0/master`](https://github.com/SpiderLabs/owasp-modsecurity-crs) branch to the current repository.

* The variables `$EMAIL_BODY` and `$EMAIL_BODY_PLAIN` now refer to unique files, that are removed after the main script finish.

* The installation script `SETUP` is compatible with Ubuntu 18.04: the package `ifupdown` must be manually installed: `sudo apt install ifupdown`.

* For more details check [stable.v.4/README.UPDATE.md][7].

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

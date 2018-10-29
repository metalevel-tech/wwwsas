# Update log

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

## Features, presented in [stable.v.1][2], not presented in the [ask_ubuntu][1] branch

* Configuration file.
* Installation script (depreciated in the next version).

 [1]: https://github.com/pa4080/www-security-assistant/tree/ask_ubuntu
 [2]: https://github.com/pa4080/www-security-assistant/tree/stable.v.1
 [3]: https://github.com/pa4080/www-security-assistant/tree/stable.v.2
 [4]: https://github.com/pa4080/www-security-assistant/blob/stable.v.2/README.OLD.md
# Issue commands to WWWSAS via the web interface

The intenition of these scripts is to provide a way to add/remove (accept/remove) an IP address to the WWWSAS's whitelist.

## Dependencies

* `sudo apt install -y oathtool` - we need it to generate TOTP tokens.

* You must know how to use TOTP 2FA authentication, e.g. what is SECRET code, atleast read [Protect SSH With Two-Factor Authentication](https://askubuntu.com/a/904035/566421).

## Setup

1. According to the main SETUP (check the main [README](../../README.md)) `/etc/sudoers.d/wwwsas-www-data-exec` must exist.

2. Do the following commands:

    ```bash
    cd /etc/wwwsas/assets/web-commands/

    sudo cp wwwsas-oathtool-code-paswd.sh /usr/local/bin/
    sudo chmod +x /usr/local/bin/wwwsas-oathtool-code-paswd.sh

    sudo cp wwwsas-web-commands.php.example /var/www/"<example.com>"/"<wwwsas-cmd>.php"
    ```

   Where:

   * `<example.com>` is the (virtual host) location, according to your Apache's setup, at which you will call the script.
   * `<wwwsas-cmd>.php` is the way you will call the php script.

3. Writedown `YOUR_2FA_PASSWORD` on a piece of paper, then within the CLI generate `php`/`sha256` of it:

    ````bash
    php -r 'echo hash ("sha256" , "YOUR_2FA_PASSWORD") . "\n";'
    ````

4. Edit (your local file) `/usr/local/bin/auth-code-password.sh`, then replace `YOUR_2FA_TOTP_SECRET` and `YOUR_2FA_PASSWORD_SHA256` with the appropriate values.

## Usage

The script `wwwsas-web-commands.php` will accept the following `GET` arguments. When everything went well, the command will be issued and the php script will return it to the web browser. When something went wrong, you will be redirected to the base location `/`. 

* `auth=` a string that consists of `YOUR_2FA_PASSWORD` and `YOUR_2FA_TOKEN`, e.g.:

    ```php
    auth=password_654321
    ```

    Where:

    * `password_` is your real password and `_` is a part of it!
    * `654321` is a token code generate on the base of `YOUR_2FA_TOTP_SECRET`.

* `cmd=` a command/option of `wwwsas` that will be executed, only `accept` and `remove` are available, e.g.:

    ```php
    cmd=accept
    ```
    ```php
    cmd=remove
    ```

* `ip=` the IPv4 address that will be whitelisted or removed from the whitelist (accept/remove).

    When `ip=` is not supplied the script will get the client's IP address.

* `note=` some notes that will be added into the whitelist file.

## *add/accept* examples

1. `https://example.com/wwwsas-cmd.php?auth=password_654321&cmd=accept&note=some_notes`

2. `https://example.com/wwwsas-cmd.php?auth=password_654321&cmd=accept&note=some_notes&ip=179.67.201.12`

3. `https://example.com/wwwsas-cmd.php?cmd=accept&note=my_mobile_isp&auth=password_654321`

## *remove* examples

1. `https://example.com/wwwsas-cmd.php?auth=password_654321&cmd=remove`

2. `https://example.com/wwwsas-cmd.php?auth=password_654321&cmd=remove&ip=179.67.201.12`

## Notes

* This feature is optional and it is not included into the main SETUP script.

* `/etc/wwwsas/` and `wwwsas.sh` are currently hardcoded in the php script.


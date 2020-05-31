# Update log

## ToDo:

* Within OWASP CRS 3.2/master the way of getting GeoIP DB is changed. An update of README.md and the SETUP script is needed. References:

   * https://dev.maxmind.com/geoip/geoipupdate/
   
   * https://github.com/maxmind/geoipupdate
   
   You need registration at https://www.maxmind.com/en/accounts/current/geoip/downloads
   
   
   ````bash
   cd /etc/modsecurity
   sudo mkdir geoipupdate
   ````
   
   
   **ModSecurity 2.9 Setup:**
   
   ````bash
   cd /etc/modsecurity
   sudo git clone https://github.com/sherpya/geolite2legacy.git
   sudo apt-get install -y python-ipaddr
   ````

   ````bash
    $ cat /etc/cron.d/wwwsas-modsec-geoipdb
    37 5 * * 5 /etc/modsecurity/geoipupdate/geoip-manual-update.sh
    ````
    
    ````bash
    $ cat /etc/modsecurity/geoipupdate/geoip-manual-update.sh
    #!/bin/sh

    LOG_FILE='/var/log/wwwsas-geoipupdate.cron.log'

    echo "# $(date) -----" >> "$LOG_FILE" 2>&1
    
    # Obtain 'license_key=' at https://www.maxmind.com/en/accounts/<USER ID>/geoip/downloads
    /usr/bin/curl 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=DDjiOKuTXVBMaGSE&suffix=zip' --output '/etc/modsecurity/geoipupdate/data/GeoLite2-Country-CSV.zip' >> "$LOG_FILE" 2>&1
    /etc/modsecurity/geolite2legacy/geolite2legacy.py -i /etc/modsecurity/geoipupdate/data/GeoLite2-Country-CSV.zip -o /etc/modsecurity/geoipupdate/data/GeoliteCountry.dat >> "$LOG_FILE" 2>&1

    echo "# ---" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE" 2>&1
    ````
    
   **ModSecurity 3.x Setup:**
   
   ````bash
   sudo add-apt-repository ppa:maxmind/ppa
   sudo apt update && sudo apt install geoipupdate
   ````
      
   ````bash
   $ cat /etc/modsecurity/geoipupdate/GeoIP.conf 
   # GeoIP.conf file for `geoipupdate` program, for versions >= 3.1.1.
   # Used to update GeoIP databases from https://www.maxmind.com.
   # For more information about this config file, visit the docs at
   # https://dev.maxmind.com/geoip/geoipupdate/.

   # `AccountID` is from your MaxMind account.
   AccountID ***277

   # Replace YOUR_LICENSE_KEY_HERE with an active license key associated 
   # with your MaxMind account.
   LicenseKey ****OKuTXVBMaGSE...

   # `EditionIDs` is from your MaxMind account.
   EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
   #EditionIDs GeoLite2-Country-CSV GeoLite2-ASN-CSV GeoLite2-City-CSV
   ````
   
   ````bash
   cd /etc/modsecurity
   sudo mkdir data
   sudo geoipupdate -f /etc/modsecurity/geoipupdate/GeoIP.conf -d /etc/modsecurity/geoipupdate/data/
   ````

   ````bash
    $ cat /etc/cron.d/wwwsas-modsec-geoipdb
    37 5 * * 5 /etc/modsecurity/geoipupdate/geoip-manual-update.sh
    ````
 
    ````bash
    $ cat geoip-manual-update.sh 
    #!/bin/sh

    LOG_FILE='/var/log/wwwsas-geoipupdate.cron.log'

    echo "# $(date) -----" >> "$LOG_FILE" 2>&1

    /usr/bin/geoipupdate -f /etc/modsecurity/geoipupdate/GeoIP.conf -d /etc/modsecurity/geoipupdate/data/ >> "$LOG_FILE" 2>&1
    
    echo "# ---" >> "$LOG_FILE" 2>&1
    echo "" >> "$LOG_FILE" 2>&1
    ````
    
    **Setup OWASP CRS 3.2/master to use the GeoIP data base**
    
    Modify `/etc/modsecurity/owasp-modsecurity-crs/crs-setup.conf` in this way:
    
    ````bash
    # For ModSecurity v3:
    #SecGeoLookupDB /etc/modsecurity/geoipupdate/data/GeoLite2-Country.mmdb
    # For ModSecurity v2 (points to the converted one):
    SecGeoLookupDB /etc/modsecurity/geoipupdate/data/GeoliteCountry.dat

    ````
    
    
* Add check for websearch bots - example for Googe bots (source: [Verifying Googlebot](https://support.google.com/webmasters/answer/80553)):

 ````bash
 $ host 66.249.66.53
 53.66.249.66.in-addr.arpa domain name pointer crawl-66-249-66-53.googlebot.com.
 ````
* Add AbuseIPDB check for modEvasive and a2Analytist.

* Fail2ban integration:

    * https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-ubuntu-14-04

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

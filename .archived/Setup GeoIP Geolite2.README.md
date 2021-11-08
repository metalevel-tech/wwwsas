Within OWASP CRS 3.2/master the way of getting GeoIP DB is changed. An update of README.md and the SETUP script is needed. References:

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
sudo apt-get install -y python-ipaddress # python-ipaddr for python < 3.2 
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
/usr/bin/curl 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip' --output '/etc/modsecurity/geoipupdate/data/GeoLite2-Country-CSV.zip' >> "$LOG_FILE" 2>&1
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

## References:

* https://www.maxmind.com/en/home
https://www.maxmind.com/en/account/login
* https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
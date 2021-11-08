#!/bin/bash

# Name:    modules/geoip-update.sh
# Summary: Update /etc/modsecurity/geolite2data/GeoIP.GeoLiteCountry.dat
#          The mechanisum used here is described in the README.md file (line ~700) of the repository.
# Home:    https://github.com/metalevel-tech/wwwsas
#
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2021
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# Obtain 'license_key=' at:
#   https://www.maxmind.com/en/accounts/<USER ID>/geoip/downloads
#
# Raw examples:
#   curl "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip" \
#         --output "/etc/modsecurity/geolite2data/GeoLite2-Country-CSV.zip"
#   curl 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip' \
#         --output '/etc/modsecurity/geolite2data/GeoLite2-City-CSV.zip'
#   cd /etc/modsecurity/geolite2data/ && \
#   ../geolite2legacy/geolite2legacy.py -i GeoLite2-Country-CSV.zip -f ../geolite2legacy/geoname2fips.csv -o GeoIP.GeoLiteCountry.dat
#
# Usage: 
# > ./geoip-update.sh
# > cat /etc/cron.d/wwwsas-geoip-update
# 37 5 * * 5 /etc/wwwsas/modules/geoip-update.sh

# -------------------------
# Environment setup section
# -------------------------

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

# The directory where the script is located - see the 'default' note in the beginning.
WORK_DIR="/etc/wwwsas"
CONF_FILE="${WORK_DIR}/wwwsas.conf"

# Load/source the configuration file
if [[ -f $CONF_FILE ]]
then
    source "${CONF_FILE}"
else
    echo "Please use \"${CONF_FILE}.example\" and create your own \"${CONF_FILE}\""
    exit 0
fi

LOG_FILE="${WWW_SAS_TMP}/geoip-update.log"
LANG=C # Set envvar $LANG to `C` due to grep, awk, etc.

# -------------
# Main function
# -------------
function geoip_update() {
    if [[ -z $MaxMindGeoLite2_LICENSE_KEY ]]
    then
        echo "You must provide a valid actual value of '\$MaxMindGeoLite2_LICENSE_KEY' within '$CONF_FILE'"
        exit 0
    else
        # EDDITION_ID='GeoLite2-City-CSV'
        EDDITION_ID='GeoLite2-Country-CSV'

        echo "# $(date) -----"

        mkdir -p  "${GEOLITE2_DATA_DIR}"

        curl "https://download.maxmind.com/app/geoip_download?edition_id=${EDDITION_ID}&license_key=${MaxMindGeoLite2_LICENSE_KEY}&suffix=zip" \
            --output "${GEOLITE2_DATA_DIR}/${EDDITION_ID}.zip"

        "${GEOLITE2_LEGACY_DIR}/geolite2legacy.py" \
            -i "${GEOLITE2_DATA_DIR}/${EDDITION_ID}.zip" \
            -f "${GEOLITE2_LEGACY_DIR}/geoname2fips.csv" \
            -o "${GEOLITE2_DATA_DIR}/GeoIP.GeoLiteCountry.dat"

        echo -e "# ---\n"
    fi
}
# -------------
# Main function Execution
# -------------
geoip_update > "$LOG_FILE" 2>&1
#!/bin/bash

# Name:    abuseipdb-push-pull-api-v1.bash - this is a deprecated version that communicates with API V1 of the service!
# Summary: Push and pull data about malicious IPs througgh AbuseIPDB's API. It is a part of the project WWW Security Assistant and
#          uses the main configuration file of the bundle to get the provided inside AbuseIPDB's API KEY.
# Home:    https://github.com/metalevel-ad/www-security-assistant
#
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# Variables that must be provided within the configuration file
# $AbuseIPDB_APIKEY
# $AbuseIPDB_totalReportsLimit
# $AbuseIPDB_abuseConfidenceScoreLimit
#
# Positional parameters:
# $1 = $IP              - the IP address object of the script. The script doesn't support CIDR yet.
# $2 = $ACTION_TYPE     - detemines how to handle the IP.
# $3 = $REPORT_CATEGORY - Category type in the 'push' mode.
# $4 = $REPORT_COMMENT  - Comment in the 'push' mode.
#
# ACTION_TYPE='pull-ip-data'      - outputs full report about the IP, if in the AbuseIPDB has record(s) for it. This is the default action.
# ACTION_TYPE='pull-ip-data-html' - same as the above, but used by the main script
# ACTION_TYPE='analyse-ip'        - outputs the AbuseScore index only, mainly used by 'www-security-assistant.bash'.
# ACTION_TYPE='push-ip-data'      - outputs the number of AbuseScore records only, mainly used by 'www-security-assistant.bash'.
# ACTION_TYPE='push-ip-data-html' - same as the above, but used by the main script
#
# Usage from the CLI
# wwwsas-abuseipdb 127.0.0.1 'pull-ip-data'
# wwwsas-abuseipdb 127.0.0.1 'analyse-ip'
# wwwsas-abuseipdb 127.0.0.1 'push-ip-data' '21,15' 'Comment'


# -------------------------
# Read the user's input
# -------------------------

[[ -z ${1+x} ]] && { echo "You must provide an IP address."; exit 0; } || IP="$1"
[[ -z ${2+x} ]] && ACTION_TYPE='pull-ip-data' || ACTION_TYPE="$2"
if [[ -z ${3+x} ]] && [[ ${2} == 'push-ip-data' ]]; then echo "In '$2' mode, one or more category must be provided."; exit 0; else REPORT_CATEGORY="$3"; fi
if [[ -z ${4+x} ]] && [[ ${2} == 'push-ip-data' ]]; then echo "In '$2' mode, a comment must be provided."; exit 0; else REPORT_COMMENT="$4"; fi


# -------------------------
# Environment setup section
# -------------------------

# The directory where the script is located - see the 'default' note in the beginning.
WORK_DIR="/etc/www-security-assistant"
CONF_FILE="${WORK_DIR}/www-security-assistant.conf"

# Load/source the configuration file
if [[ -f $CONF_FILE ]]
then
    source "${CONF_FILE}"
else
    echo "Please use \"${CONF_FILE}.example\" and create your own \"${CONF_FILE}\""
    exit 0
fi


# -----------------------------
# AbuseIPDB Categories as array
# -----------------------------

AbuseIPDB_CATEGORY=('https://www.abuseipdb.com/categories')
AbuseIPDB_CATEGORY[1]='[1] NA'
AbuseIPDB_CATEGORY[2]='[2] NA'
AbuseIPDB_CATEGORY[3]='[3] Fraud Orders'     # Fraudulent orders.
AbuseIPDB_CATEGORY[4]='[4] DDoS Attack'      # Participating in distributed denial-of-service [usually part of botnet].
AbuseIPDB_CATEGORY[5]='[5] FTP Brute-Force'  #
AbuseIPDB_CATEGORY[6]='[6] Ping of Death'    # Oversized IP packet.
AbuseIPDB_CATEGORY[7]='[7] Phishing'         # Phishing websites and/or email.
AbuseIPDB_CATEGORY[8]='[8] Fraud VoIP'       #
AbuseIPDB_CATEGORY[9]='[9] Open Proxy'       # Open proxy, open relay, or Tor exit node.
AbuseIPDB_CATEGORY[10]='[10] Web Spam'       # Comment/forum spam, HTTP referer spam, or other CMS spam.
AbuseIPDB_CATEGORY[11]='[11] Email Spam'     # Spam email content, infected attachments, phishing emails, and spoofed senders [typically via exploited host or SMTP server abuse].
AbuseIPDB_CATEGORY[12]='[12] Blog Spam'      # CMS blog comment spam.
AbuseIPDB_CATEGORY[13]='[13] VPN IP'         # Conjunctive category.
AbuseIPDB_CATEGORY[14]='[14] Port Scan'      # Scanning for open ports and vulnerable services.
AbuseIPDB_CATEGORY[15]='[15] Hacking'        #
AbuseIPDB_CATEGORY[16]='[16] SQL Injection'  # Attempts at SQL injection.
AbuseIPDB_CATEGORY[17]='[17] Spoofing'       #
AbuseIPDB_CATEGORY[18]='[18] Brute-Force'    # Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc.
AbuseIPDB_CATEGORY[19]='[19] Bad Web Bot'    # Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt.
AbuseIPDB_CATEGORY[20]='[20] Exploited Host' # Host is likely infected with malware and being used for other attacks or to host malicious content.
AbuseIPDB_CATEGORY[21]='[21] Web App Attack' # Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, forum software, phpMyAdmin and various other software plugins/solutions.
AbuseIPDB_CATEGORY[22]='[22] SSH'            # Secure Shell (SSH) abuse. Use this category in combination with more specific categories.
AbuseIPDB_CATEGORY[23]='[23] IoT Targeted'   # Abuse was targeted at an "Internet of Things" type device. Include information about what type of device was targeted in the comments.


# -----------------------------
# The Main Script
# -----------------------------

# Get the data about the object IP address
pull_ip_data() {
    if [[ -z $AbuseIPDB_APIKEY ]]
    then
        echo "You must provide a valid actual value of '\$AbuseIPDB_APIKEY' within '$CONF_FILE'"
        exit 0
    else
        # Example: https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
        AbuseIPDB_IP_DATA="$(wget -O - -o /dev/null "https://www.abuseipdb.com/check/${IP}/json?key=${AbuseIPDB_APIKEY}&days=365" | sed -e 's/^\[//' -e 's/\]$//')"

        if [[ -z $AbuseIPDB_IP_DATA ]]
        then
            if [[ $HTML == 'YES' ]]
            then
                echo "<b>There is not data about the IP address $IP.</b>"
                exit 0
            else
                echo "There is not data about the IP address $IP."
                exit 0
            fi

        else
            AbuseIPDB_IP_DATA="$(echo "$AbuseIPDB_IP_DATA" | sed 's#}\,{#}\n{#g' )"

            AbuseIPDB_IP_CATEGORY="$(echo "$AbuseIPDB_IP_DATA" | sed -nr 's#^.*"category":\[(.*)\].*$#\1#p' | sed 's#\,#\n#g' | sort -u -g | sed ':a;N;$!ba;s#\n# #g')"
            AbuseIPDB_IP_CATEGORY_COUNT="$(echo "$AbuseIPDB_IP_DATA" | sed -nr 's#^.*"category":\[(.*)\].*$#\1#p' | sed 's#\,#\n#g' | sort -u | wc -l)"
            AbuseIPDB_IP_CATEGORY_VERBOSE="$(for CATEGORY in $AbuseIPDB_IP_CATEGORY; do echo -n "${AbuseIPDB_CATEGORY[$CATEGORY]}, "; done | sed 's/, $//')"
            AbuseIPDB_IP_RECORDS_NUMBER="$(echo "$AbuseIPDB_IP_DATA" | grep -c "$IP")"
            AbuseIPDB_IP_COUNTRY="$(echo "$AbuseIPDB_IP_DATA" | tail -1 | sed -nr 's#^.*"country":"(.*)","isoCode".*$#\1#p')"
            AbuseIPDB_IP_ISOCODE="$(echo "$AbuseIPDB_IP_DATA" | tail -1 | sed -nr 's#^.*"isoCode":"(.*)","isWhitelisted".*$#\1#p')"
            AbuseIPDB_IP_ISWHITELISTED="$(echo "$AbuseIPDB_IP_DATA" | tail -1 | sed -nr 's#^.*"isWhitelisted":(.*),"abuseConfidenceScore".*$#\1#p')"
            AbuseIPDB_IP_ABUSESCORE="$(echo "$AbuseIPDB_IP_DATA" | tail -1 | sed -nr 's#^.*"abuseConfidenceScore":(.*)}$#\1#p')"
        fi
    fi
}

# Report the object IP address
push_ip_data() {
    if [[ -z $AbuseIPDB_APIKEY ]]
    then
        echo "You must provide a valid value of '\$AbuseIPDB_APIKEY' within '$CONF_FILE'"
        exit 0
    else
        # Example: https://www.abuseipdb.com/report/json?key=[API_KEY]&category=[CATEGORIES]&comment=[COMMENT]&ip=[IP]
        AbuseIPDB_IP_DATA="$(wget -O - -o /dev/null "https://www.abuseipdb.com/report/json?key=${AbuseIPDB_APIKEY}&category=${REPORT_CATEGORY}&comment=${REPORT_COMMENT}&ip=${IP}")"

        if [[ $AbuseIPDB_IP_DATA =~ success.*true ]]
        then

            if [[ $HTML == 'YES' ]]
            then
                echo "The IP address $IP <i>was successfully reported</i> to AbuseIPDB."
            else
                echo "The IP address $IP was successfully reported to AbuseIPDB."
            fi

        else

            if [[ $HTML == 'YES' ]]
            then
                echo "The IP address $IP <i>wasn't reported</i> to AbuseIPDB, probably it have been reported within the last 15 minutes."
            else
                echo "The IP address $IP wasn't reported to AbuseIPDB, probably it have been reported within the last 15 minutes."
            fi

        fi
    fi
}

# Response according to the action type
if   [[ $ACTION_TYPE == 'pull-ip-data' ]]
then
    pull_ip_data
    echo "Category:       $AbuseIPDB_IP_CATEGORY"
    echo "Category Count: $AbuseIPDB_IP_CATEGORY_COUNT (Limit: $AbuseIPDB_CategoryCountLimit)"
    echo "Category:       $AbuseIPDB_IP_CATEGORY_VERBOSE"
    echo "Country:        $AbuseIPDB_IP_COUNTRY"
    echo "ISOCode:        $AbuseIPDB_IP_ISOCODE"
    echo "Is Whitelisted: $AbuseIPDB_IP_ISWHITELISTED"
    echo "Abuse Score:    $AbuseIPDB_IP_ABUSESCORE (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
    echo "Records Number: $AbuseIPDB_IP_RECORDS_NUMBER (Limit: $AbuseIPDB_totalReportsLimit)"
elif [[ $ACTION_TYPE == 'pull-ip-data-html' ]]
then
    HTML='YES'
    pull_ip_data
    echo "<b>AbuseIPDB data report for $IP</b>"
    echo "Category:       $AbuseIPDB_IP_CATEGORY"
    echo "Category:       $AbuseIPDB_IP_CATEGORY_VERBOSE"
    echo "Country:        <b>$AbuseIPDB_IP_COUNTRY</b>"
    echo "ISOCode:        <b>$AbuseIPDB_IP_ISOCODE</b>"
    echo "Is Whitelisted: $AbuseIPDB_IP_ISWHITELISTED"
    echo "Category Count: <b>$AbuseIPDB_IP_CATEGORY_COUNT</b> (Limit: $AbuseIPDB_CategoryCountLimit)"
    echo "Abuse Score:    <b>$AbuseIPDB_IP_ABUSESCORE</b> (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
    echo "Records Number: <b>$AbuseIPDB_IP_RECORDS_NUMBER</b> (Limit: $AbuseIPDB_totalReportsLimit)"
elif [[ $ACTION_TYPE == 'analyse-ip' ]]
then
    pull_ip_data
    if [[ $AbuseIPDB_IP_RECORDS_NUMBER -ge "$AbuseIPDB_totalReportsLimit" || $AbuseIPDB_IP_ABUSESCORE -ge "$AbuseIPDB_abuseConfidenceScoreLimit" || $AbuseIPDB_IP_CATEGORY_COUNT -ge "$AbuseIPDB_CategoryCountLimit" ]] 
    then
        echo 'Bad Guy'
    else
        echo "Records Number: $AbuseIPDB_IP_RECORDS_NUMBER (Limit: $AbuseIPDB_totalReportsLimit)"
        echo "Abuse Score:    $AbuseIPDB_IP_ABUSESCORE (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
        echo "Category Count: $AbuseIPDB_IP_CATEGORY_COUNT (Limit: $AbuseIPDB_CategoryCountLimit)"
    fi
elif [[ $ACTION_TYPE == 'push-ip-data' ]]
then
    push_ip_data
elif [[ $ACTION_TYPE == 'push-ip-data-html' ]]
then
    HTML='YES'
    push_ip_data
elif [[ $ACTION_TYPE == 'categories' ]]
then
    printf '%s\n' "${AbuseIPDB_CATEGORY[@]}"
else
    echo "Unlnown Action Type: '$ACTION_TYPE'."
fi

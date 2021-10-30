#!/bin/bash

# Name:    abuseipdb-push-pull.bash
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
# ACTION_TYPE='categories'        - outputs all available report categories.
# ACTION_TYPE='pull-ip-data'      - outputs full report about the IP, if in the AbuseIPDB has record(s) for it. This is the default action.
# ACTION_TYPE='pull-ip-data-html' - same as the above, but used by the main script
# ACTION_TYPE='pull-ip-data-table'- used to generate a table within while/ for loop: for ip in "$IPS[@]"; do wwwsas-abuseipdb "$IP" 'pull-ip-data-table'; done
# ACTION_TYPE='analyse-ip'        - outputs the AbuseScore index only, mainly used by 'www-security-assistant.bash'.
# ACTION_TYPE='push-ip-data'      - outputs the number of AbuseScore records only, mainly used by 'www-security-assistant.bash'.
# ACTION_TYPE='push-ip-data-html' - same as the above, but used by the main script
#
# Usage from the CLI
# wwwsas-abuseipdb '' 'categories'
# wwwsas-abuseipdb 127.0.0.1 'pull-ip-data'
# wwwsas-abuseipdb 127.0.0.1 'pull-ip-data-table-header'
# wwwsas-abuseipdb 127.0.0.1 'pull-ip-data-table'
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
AbuseIPDB_CATEGORY[1]='[1] DNS Compromise'   # Altering DNS records resulting in improper redirection.
AbuseIPDB_CATEGORY[2]='[2] DNS Poisoning'    # Falsifying domain server cache (cache poisoning).
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
AbuseIPDB_CATEGORY[17]='[17] Spoofing'       # Email sender spoofing.
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

        # Example API V1: https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
        #AbuseIPDB_IP_DATA="$(wget -O - -o /dev/null "https://www.abuseipdb.com/check/${IP}/json?key=${AbuseIPDB_APIKEY}&days=365" | sed -e 's/^\[//' -e 's/\]$//')"

    	# Example API V2: curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=127.0.0.1" -d maxAgeInDays=90 -d verbose -H "Key: $YOUR_API_KEY" -H "Accept: application/json"
        AbuseIPDB_IP_DATA="$(curl -G -s https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${IP}" -d maxAgeInDays=365 -d verbose -H "Key: ${AbuseIPDB_APIKEY}" -H "Accept: application/json")"

        AbuseIPDB_lastReportedAt="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .reportedAt' | sed 's/"//g')"
        if [[ $AbuseIPDB_lastReportedAt == 'null' ]]
        then
            AbuseIPDB_lastReportedAt="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .lastReportedAt' | sed 's/"//g')"
        fi

        if [[ $AbuseIPDB_lastReportedAt =~ 'null' ]]
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

            #echo "$AbuseIPDB_IP_DATA" | jq
            #echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .lastReportedAt'    | sed 's/"//g'
            #echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .reportedAt'    | sed 's/"//g'
            #echo '---::---'

            AbuseIPDB_ipAddress="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .ipAddress' | sed 's/\"//g')"
            AbuseIPDB_totalReports="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .totalReports')"
            AbuseIPDB_numDistinctUsers="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .numDistinctUsers')"
            AbuseIPDB_countryName="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .countryName' | sed 's/\"//g')"
            AbuseIPDB_countryCode="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .countryCode' | sed 's/\"//g')"
            AbuseIPDB_abuseConfidenceScore="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .abuseConfidenceScore')"
            AbuseIPDB_isWhitelisted="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .isWhitelisted')"
            AbuseIPDB_isPublic="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .isPublic')"
            AbuseIPDB_ipVersion="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .ipVersion')"

            AbuseIPDB_usageType="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .usageType' | sed 's/\"//g')"
            AbuseIPDB_isp="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .isp' | sed 's/\"//g')"
            AbuseIPDB_domain="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .domain' | sed 's/\"//g')"
            AbuseIPDB_hostnames="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .hostnames[]' | sed 's/\"//g' | tr '\n' ' ')"

            AbuseIPDB_categoryList="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .reports[] | .categories[]' | sort -u | tr '\n' ' ')"
            AbuseIPDB_categoryCount="$(echo "$AbuseIPDB_IP_DATA" | /usr/bin/jq '.data | .reports[] | .categories[]' | sort -u | wc -l)"
            AbuseIPDB_categoryListVerbose="$(for CATEGORY in $AbuseIPDB_categoryList; do echo -n "${AbuseIPDB_CATEGORY[$CATEGORY]}, "; done | sed 's/, $//')"

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

        # Example API V1: https://www.abuseipdb.com/report/json?key=[API_KEY]&category=[CATEGORIES]&comment=[COMMENT]&ip=[IP]
        #AbuseIPDB_IP_DATA="$(wget -O - -o /dev/null "https://www.abuseipdb.com/report/json?key=${AbuseIPDB_APIKEY}&category=${REPORT_CATEGORY}&comment=${REPORT_COMMENT}&ip=${IP}")"

        # Example API V2: curl -s https://api.abuseipdb.com/api/v2/report --data-urlencode "ip=127.0.0.1" -d categories=18,22 --data-urlencode "comment=SSH login attempts with user root." -H "Key: $YOUR_API_KEY" -H "Accept: application/json"
        AbuseIPDB_IP_DATA="$(curl -s https://api.abuseipdb.com/api/v2/report --data-urlencode "ip=${IP}" -d categories=${REPORT_CATEGORY} --data-urlencode "comment=${REPORT_COMMENT}" -H "Key: ${AbuseIPDB_APIKEY}" -H "Accept: application/json")"

        AbuseIPDB_abuseConfidenceScore_onReport="$(echo "$AbuseIPDB_IP_DATA" | sed -nr 's#^.*"abuseConfidenceScore":([0-9]+)}}.*$#\1#p')"
        AbuseIPDB_errorHandle_onReport="$(echo "$AbuseIPDB_IP_DATA" | sed -nr 's/^.*"detail":"(.*\.)","status":.*$/\1/p' | sed 's/`//g')"

        if [[ ! -z $AbuseIPDB_abuseConfidenceScore_onReport ]]
        then

            if [[ $HTML == 'YES' ]]
            then
                echo "The IP address $IP <i>was successfully reported</i> to AbuseIPDB - abuse confidence score $AbuseIPDB_abuseConfidenceScore_onReport."
            else
                echo "The IP address $IP was successfully reported to AbuseIPDB - abuse confidence score $AbuseIPDB_abuseConfidenceScore_onReport."
            fi

        else

            if [[ $HTML == 'YES' ]]
            then
                echo "The IP address $IP <i>wasn't reported</i> to AbuseIPDB. $AbuseIPDB_errorHandle_onReport"
            else
                echo "The IP address $IP wasn't reported to AbuseIPDB. $AbuseIPDB_errorHandle_onReport"
            fi

        fi

    fi

}

# Response according to the action type
if   [[ $ACTION_TYPE == 'pull-ip-data' ]]
then

    pull_ip_data

    echo "IP Address:     $AbuseIPDB_ipAddress"
    echo "Total Reports:  $AbuseIPDB_totalReports (Limit: $AbuseIPDB_totalReportsLimit)"
    echo "Distinct Users: $AbuseIPDB_numDistinctUsers"
    echo "Country Name:   $AbuseIPDB_countryName"
    echo "Country Code:   $AbuseIPDB_countryCode"
    echo "Abuse Score:    $AbuseIPDB_abuseConfidenceScore (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
    echo "Is Whitelisted: $AbuseIPDB_isWhitelisted"
    echo "Is Public:      $AbuseIPDB_isPublic"
    echo "IP Version:     $AbuseIPDB_ipVersion"
    echo "Category Count: $AbuseIPDB_categoryCount (Limit: $AbuseIPDB_CategoryCountLimit)"
    echo "Category List:  $AbuseIPDB_categoryList"
    echo "Category Verb.: $AbuseIPDB_categoryListVerbose"
    echo "Usage Type:     $AbuseIPDB_usageType"
    echo "ISP:            $AbuseIPDB_isp"
    echo "Domain:         $AbuseIPDB_domain"
    echo "Hostnames:      $AbuseIPDB_hostnames"
    echo "Last Report At: $AbuseIPDB_lastReportedAt"

elif [[ $ACTION_TYPE == 'pull-ip-data-html' ]]
then

    HTML='YES'
    pull_ip_data

    echo "<b>AbuseIPDB data report for $AbuseIPDB_ipAddress</b>"
    echo "Total Reports:  <b>$AbuseIPDB_totalReports</b> (Limit: $AbuseIPDB_totalReportsLimit)"
    echo "Distinct Users: $AbuseIPDB_numDistinctUsers"
    echo "Country Name:   <b>$AbuseIPDB_countryName</b>"
    echo "Country Code:   <b>$AbuseIPDB_countryCode</b>"
    echo "Abuse Score:    <b>$AbuseIPDB_abuseConfidenceScore</b> (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
    echo "Is WL/Public:   $AbuseIPDB_isWhitelisted/$AbuseIPDB_isPublic"
    echo "Category Count: <b>$AbuseIPDB_categoryCount</b> (Limit: $AbuseIPDB_CategoryCountLimit)"
    echo "Category List:  $AbuseIPDB_categoryList"
    echo "Category Verb.: $AbuseIPDB_categoryListVerbose"
    echo "Usage Type:     $AbuseIPDB_usageType"
    echo "ISP:            $AbuseIPDB_isp"
    echo "Domain:         $AbuseIPDB_domain"
    echo "Hostnames:      $AbuseIPDB_hostnames"

elif   [[ $ACTION_TYPE == 'pull-ip-data-table' ]]
then

    pull_ip_data

    # These variables are not included: $AbuseIPDB_usageType $AbuseIPDB_isp $AbuseIPDB_domain $AbuseIPDB_hostnames
    printf '%s\t%-32s%s\t%s\t%s\t%s\t%s\t%s\n' "$AbuseIPDB_countryCode" "$AbuseIPDB_countryName" "$AbuseIPDB_ipAddress" "$AbuseIPDB_totalReports" "$AbuseIPDB_numDistinctUsers" "$AbuseIPDB_abuseConfidenceScore" "$AbuseIPDB_categoryCount" "$AbuseIPDB_isWhitelisted"

elif   [[ $ACTION_TYPE == 'pull-ip-data-table-header' ]]
then

    # These variables are not included: $AbuseIPDB_usageType $AbuseIPDB_isp $AbuseIPDB_domain $AbuseIPDB_hostnames
    printf 'Code\tCoutry Name\tIP Address\tReports\tUsrers\tScore\tCatCnt\tWhitelisted\n'

elif [[ $ACTION_TYPE == 'analyse-ip' ]]
then

    pull_ip_data

    if [[ $AbuseIPDB_totalReports -ge "$AbuseIPDB_totalReportsLimit" || $AbuseIPDB_abuseConfidenceScore -ge "$AbuseIPDB_abuseConfidenceScoreLimit" || $AbuseIPDB_categoryCount -ge "$AbuseIPDB_CategoryCountLimit" ]] 
    then

        echo 'Bad Guy'

    else

        echo "Total Reports:  $AbuseIPDB_totalReports (Limit: $AbuseIPDB_totalReportsLimit)"
        echo "Abuse Score:    $AbuseIPDB_abuseConfidenceScore (Limit: $AbuseIPDB_abuseConfidenceScoreLimit)"
        echo "Category Count: $AbuseIPDB_categoryCount (Limit: $AbuseIPDB_CategoryCountLimit)"

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

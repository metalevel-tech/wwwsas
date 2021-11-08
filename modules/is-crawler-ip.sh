#!/bin/bash

# Name:    modules/is-crawler-ip.sh
# Summary: Test wheather an IP address is some known crawler
#          uses the main configuration file of the bundle.
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
# References:
# > https://developers.google.com/search/docs/advanced/crawling/verifying-googlebot
# > https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
# > https://www.bing.com/toolbox/verify-bingbot
# > https://help.duckduckgo.com/duckduckgo-help-pages/results/duckduckbot/
# > https://developers.facebook.com/docs/sharing/webmasters/crawler
# > https://community.cloudflare.com/t/legit-yandex-search-bot-blocked-by-firewall/312177
# > https://yandex.com/support/webmaster/robot-workings/check-yandex-robots.html
# > https://www.sitepoint.com/community/t/anyone-dealt-with-the-baiduspider-bot/4767/2
# > https://www.looklinux.com/robots-crawlers-ip-address-ranges-googlebot-yahoo-slurp-msnbot-bing-etc/
#
# Usage: 
# > ./is-crawler.sh 66.249.66.1            # googlebot; this mode has verbose output (the logging is disabled)
# > ./is-crawler.sh 66.249.66.1 'AutoMode' # this makes verbose log entry, but returns limited output, used by wwwsas.sh

# -------------------------
# Read the user's input
# -------------------------

[[ -z ${1+x} ]] && { echo "You must provide an IP address."; exit 0; } || IP="$1"
[[ -z ${2+x} ]] && ACTION_TYPE='CLIMode' || ACTION_TYPE="$2"

# -------------------------
# Environment setup section
# -------------------------

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

LOG_FILE="${WWW_SAS_LOG}/is-crawler-ip.log"
LANG=C # Set envvar $LANG to `C` due to grep, awk, etc.

# -------------
# Main function
# -------------
function is_crawler() {
    IFS=$'\n'
    local IP="${1}"
    local CRAWLERS=('googlebot.com' 'spider.yandex.com' 'msedge.net' 'search.msn.com' 'duckduckgo.com' 'crawl.baidu.com' 'yahoo.com' 'facebook.com')
    local IP_HOST_RAW=( $(host "$IP" | sed -r 's/\.$//' 2>/dev/null) )
    local IP_HOST="$(printf '%s\n' "${IP_HOST_RAW[@]}" | awk '{print $NF}' )"

    for crawler in ${CRAWLERS[@]}
    do
        IP_REVERSE=$(sed -r 's/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/\4\\.\3\\.\2\\.\1/' <<< $IP)
        TEST_LINE=$(printf '%s\n' "${IP_HOST_RAW[@]}" | grep -o "${IP_REVERSE}.*pointer.*${crawler}")

        if [[ ! -z ${TEST_LINE} ]]
        then
            MATCHED_HOST=$(awk '{print $NF}' <<< ${TEST_LINE})
            HOST_IP="$(host "$MATCHED_HOST")"
            IP_TEST=$(sed 's/\./\\./g' <<< $IP)

            if grep -ioq -- "$IP_TEST" <<< "$HOST_IP"
            then

                if   [[ $ACTION_TYPE == 'AutoMode' ]]
                then
                    if [[ $REPORT_MODE_CRAWLER == 'verbose' ]]
                    then
                    {   printf '\n[TRUE_CRAWLER] %s %s (%s | %s)\n' "${MATCHED_HOST^^}" "$IP" "$(date)" "$ACTION_TYPE"
                        printf '> %s\n' ${IP_HOST_RAW[@]}
                        printf '< %s\n' ${HOST_IP} 
                    } >> "$LOG_FILE"
                        printf '[TRUE_CRAWLER] %s %s' "${MATCHED_HOST^^}" "$IP"
                    else
                        printf '\n' >> "$LOG_FILE"
                        printf '[TRUE_CRAWLER] %s %s' "${MATCHED_HOST^^}" "$IP" | tee -a "$LOG_FILE"
                        printf '\n' >> "$LOG_FILE"
                    fi
                else
                    # if [[ $REPORT_MODE_CRAWLER == 'verbose' ]]
                    # then
                    {   printf '\n[TRUE_CRAWLER] %s %s (%s | %s)\n' "${MATCHED_HOST^^}" "$IP" "$(date)" "$ACTION_TYPE"
                        printf '> %s\n' ${IP_HOST_RAW[@]}
                        printf '< %s\n' ${HOST_IP}
                    } #| tee -a "$LOG_FILE"
                        # printf '\n[TRUE_CRAWLER] %s %s (%s)\n' "${MATCHED_HOST^^}" "$IP" "$(date)"
                    # else
                    #     printf '\n[TRUE_CRAWLER] %s %s (%s | %s)\n' "${MATCHED_HOST^^}" "$IP" "$(date)" "$ACTION_TYPE" | tee -a "$LOG_FILE"
                    # fi
                fi
                exit
            #else
                # We cannot conclude so easy it is fake, the parser rules must be more pedantic...
                # - or mayme theya are already strong enough??
                # printf '[FAKE_CRAWLER] %s %s\n> %s\n> %s' "${crawler^^}" "$IP" "$IP_HOST_RAW" "$HOST_IP"
                # exit
            fi
        fi
    done
    printf '[NOT_CRAWLER] %s ' "$IP"
    exit
}

# -------------
# Main function Execution
# -------------
is_crawler "${1}"
#!/bin/sh

# Name: modsecurity-assistant.sh [default work directory /var/www-security-assistant]
# Summary: Custom script designed to handle data from ModSecurity throug the 'exec' action
# Home: https://github.com/pa4080/security-assistant
# Author: Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.

# Set th environment variables
TIME="$(date +%H:%M:%S)"
DATE="$(date +%Y-%m-%d)"
WORK_DIR="/var/www-security-assistant"
SEC_ASSISTANT="${WORK_DIR}/www-security-assistant.bash"
EXEC_LOG="${WORK_DIR}/www-security-assistant.execlog"


# This step solves an old issue and it is not longer needed - but why not :) MY_DIVIDER='-DiViDeR-d1v1d3r-'
MY_DIVIDER="$(grep '^MY_DIVIDER' "$SEC_ASSISTANT" | sed -r "s/^MY_DIVIDER='(-.*-)'.*$/\1/")"

# Output a log header
printf '\n\n***** SECURITY LOG from %s on %s : modsecurity-assistant.sh >>' "$TIME" "$DATE" >> "$EXEC_LOG" 2>&1

# Apply some filter to $REQUEST_URI, for example substitute the latin letters "X" and "x" with the cyrillic letters "Х" and "х".
# This step solves an old issue and it is not longer needed - but why not :)
REQUEST_URI="$(echo ${REQUEST_URI} | sed -e 's/0/О/g' -e 's/p/р/g' -e 's/P/Р/g' -e 's/x/х/g' -e 's/X/Х/g' -e 's/A/А/g' -e 's/a/а/g')"

# Compose the log note
ATTACK_INFO="Attacking IP: ${REMOTE_ADDR}${MY_DIVIDER}Attack. host: ${REMOTE_HOST}${MY_DIVIDER}Unique ID: ${UNIQUE_ID}${MY_DIVIDER}Our Server: ${SERVER_NAME}${MY_DIVIDER}Request URI: ${REQUEST_URI}${MY_DIVIDER}Arguments: ${ARGS}"

# Call WWW Security Assistant Script
exec sudo "$SEC_ASSISTANT" "$REMOTE_ADDR" 'ModSecurity' "$ATTACK_INFO" >> "$EXEC_LOG" 2>&1

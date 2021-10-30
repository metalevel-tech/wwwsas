#!/bin/bash -e

# Name:    modsecurity-assistant.bash - example port between ModSecurity and WWWSecurityAssistant.
# Summary: Custom script designed to handle data from ModSecurity throug the 'exec' action.
# Home:    https://github.com/metalevel-ad/www-security-assistant
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.


# -------------------------
# Environment setup section
# -------------------------

# The directory where the script is located - see the 'default' note in the beginning.
WORK_DIR="/etc/www-security-assistant"
CONF_FILE="${WORK_DIR}/www-security-assistant.conf"

# Load/source the configuration file
if [[ -f "$CONF_FILE" ]]
then
    source "$CONF_FILE"
else
    echo "Please use \"${CONF_FILE}.example\" and create your own \"${CONF_FILE}\""
    exit 0
fi


# -------------------------
# The main script section
# -------------------------

## Output a log header
printf '\n\n*****\nSECURITY LOG from %s on %s : modsecurity-assistant.bash >>\n--- Rule ID: %s -----\n' "$TIME" "$DATE" "${RULE_ID}">> "$WWW_SAS_EXEC_LOG" 2>&1

# Compose the log note
ATTACK_INFO="Attacking IP: ${REMOTE_ADDR}${MY_DIVIDER}Unique ID: ${UNIQUE_ID}${MY_DIVIDER}Our Server: ${SERVER_NAME}${MY_DIVIDER}Request URI: ${REQUEST_URI}${MY_DIVIDER}Arguments: ${ARGS}${MY_DIVIDER}"

# Call WWW Security Assistant Script
exec sudo "$WWW_SAS_EXEC" "$REMOTE_ADDR" 'ModSecurity' "$ATTACK_INFO" "$RULE_ID" "$REQUEST_URI" >> "$WWW_SAS_EXEC_LOG" 2>&1 &

exit 0

#!/bin/bash -e

# Name:    modsecurity-whitelist-rule-generator.bash
# Summary: The tool is able to parse the ModSecurity's audit log file (modsec_audit.log) and
#          generate whitelisting rules, based on the REQUEST_URI. The necessary configuration data must be provided within www-security-assistant.conf.
#
# Home:    https://github.com/pa4080/www-security-assistant
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# Usage
# $1 - The new Rule Number ID 
#      When the value is '999999' the script will parse and calculate the id number automatically, based on the values of
#      $MOD_SECURITY_WHITELIST_FILE and $SECURITY_RULE_PARSE_METHOD from the configuration file.
#      When the value is 'active-rules' (used by 'www-security-assistant.bash'), it just will output information about the rules involved in the thread.
# $2 - Type of the analysis: `latest-log` or `unique-id`
# $3 - The Unique ID of the log record (action)
# $4 - Default Method: `request`; The methods are not available at the moment: `cookie` `request cookie`; This variable is not manatory at the moment
#
# The common call syntax is:
#      wwwsas-mswlrg '999999'|'active-rules' ['latest-log'|'unique-id' '27-CharactersLong-UniqueID']


# -------------------------
# Read the user's input
# -------------------------

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

[[ -z ${1+x} ]] && RULE_NUMBER='999999' || RULE_NUMBER="$1"
[[ -z ${2+x} ]] && ANALYSIS_TYPE='latest-log' || ANALYSIS_TYPE="$2"
[[ -z ${3+x} ]] && UNIQUE_ID='The Unique ID must be 27 characters long!' || UNIQUE_ID="$3"


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

LOG_FILE="/tmp/www-security-assistant-modsec_audit_cat.log"
TMP_FILE="/tmp/www-security-assistant-modsec_audit_cat.tmp"
cat "$MOD_SECURITY_AUDIT_LOG"{.1,} > "$LOG_FILE"

# Output colors
RED='\033[0;31m'
GRE='\033[0;32m'
YEL='\033[1;33m'
NCL='\033[0m'   # No color


# ---------------------------------
# Functions used in the main script
# ---------------------------------

get_info() {
	REMOTE_IP="$(sed -n -r 's/^\[.*\] .{28}([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) [0-9]+ .*$/\1/p' "$TMP_FILE")"
	LOCAL_HOST="$(sed -r -n 's/^Host: (.*)$/\1/p' "$TMP_FILE")"
	REQUEST_FULL="$(sed -r -n 's/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (.*) (HTTP.*)$/\1 \2 \3/p' "$TMP_FILE")"
	ORIGIN_URL="$(sed -r -n 's/^Origin: (http.*)$/\1/p' "$TMP_FILE")"
	REFERER_URL="$(sed -r -n 's/^Referer: (http.*)$/\1/p' "$TMP_FILE")"

	REQUEST_URI="$(sed -r -n 's/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (.*) (HTTP.*)$/\2/p' "$TMP_FILE")"
	REQUEST_URI_FILTRED="$(echo "$REQUEST_URI" | sed -r -e 's/\?/\\\?/g' -e 's/=[0-9]+/=\[0-9\]\+/g')"

	COOKIE="$(sed -n -r 's/^Cookie: (.*)/\1/p' "$TMP_FILE")"

	UNIQUE_ID_PARSED="$(sed -n -r 's/^\[.*\] (.{28})[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ [0-9]+ .*$/\1/p' "$TMP_FILE")"
}

head_message() {
	echo
	echo -e "To whitelist actions similar to unique ID: ${YEL}${UNIQUE_ID_PARSED}${NCL}(parsed value), "
	echo "copy the balow rule and press [Enter] to execute the commands:"
	echo
	echo "    nano $MOD_SECURITY_WHITELIST_FILE"
	echo "    systemctl reload apache2.service"
	echo "    systemctl status apache2.service"
}

rule_number() {
	# Compose the number ot the new modsec rule
	if [[ $RULE_NUMBER == '999999' ]] && [[ $SECURITY_RULE_PARSE_METHOD == 'latest' ]]
	then
	    RULE_NUMBER=$(( $(grep -oP "id:'\K[0-9]{6}" "$MOD_SECURITY_WHITELIST_FILE" | tail -1) + 1 ))
	elif [[ $RULE_NUMBER == '999999' ]] && [[ $SECURITY_RULE_PARSE_METHOD == 'greatest' ]]
	then
	    RULE_NUMBER=$(( $(grep -oP "id:'\K[0-9]{6}" "$MOD_SECURITY_WHITELIST_FILE" | sort -u | tail -1) + 1 ))
	else
	    RULE_NUMBER="$1"
	fi
}

rule_info() {
	echo "# Whitelist Rule $RULE_NUMBER Info -----"
	echo "#"
	echo "# Remote IP: $REMOTE_IP"
	echo "# Host:      $LOCAL_HOST"
	echo "# Request:   $REQUEST_FULL"
	echo "# Origin:    $ORIGIN_URL"
	echo "# Referer:   $REFERER_URL"
	echo "#"
}

rule_body() {
	printf "\nSecRule REQUEST_URI \"^%s$\" \\" "$REQUEST_URI_FILTRED"; echo
	printf "\t\"id:'%s', t:none, phase:1, pass, nolog, \\" "$RULE_NUMBER"; echo
	sed -r -n 's/.*\[id \"([0-9]+)\"\].*$/\t ctl:ruleRemoveById=\1\, \\/p' "$TMP_FILE" | sort -u | sed '$ s/\, \\/\"/'
}

# This function is used by the 'active-rules' mode and oputput only the ModSecurity's RuleIDs, active within the thread
active_rules() {

	printf '<b>ModSecurity thread parameters: RuleId, Tag(s)</b>\n' #"$UNIQUE_ID"

	# Output also the files, that contain the rules
	#printf '<b>ModSecurity thread parameters: RuleId, Tag(s); File(s) <span style="color: transparent; font-size: 6px;">Unique_ID: %s</span></b>\n' "$UNIQUE_ID"

	# This could be possible to be done with single `sed` command
	if grep -q 'tag' "$TMP_FILE"
	then	# When there have tag(s)

		sed 's/\[tag /\[Tags: /' "$TMP_FILE" | sed 's/\] \[tag / /g' | sed -r -n 's/^.*\[file "(.*)"\] \[line.*\[id "([0-9]+)"\].*\[Tags: (".*")\] \[hostname.*$/<b>\2<\/b>, \L\3\E/p' | sort -u

		# Output also the files, that contain the rules
		#sed 's/\[tag /\[Tags: /' "$TMP_FILE" | sed 's/\] \[tag / /g' | sed -r -n 's/^.*\[file "(.*)"\] \[line.*\[id "([0-9]+)"\].*\[Tags: (".*")\] \[hostname.*$/\/\2, \L\3\E, \1/p' | sed -r 's/", (.*)$/"\n\1/' | sort -u

	else	# When there have not tag(s)

		sed 's/\[tag /\[Tags: /' "$TMP_FILE" | sed 's/\] \[tag / /g' | sed -r -n 's/^.*\[file "(.*)"\] \[line.*\[id "([0-9]+)".*$/<b>\2<\/b>/p' | sort -u

		# Output also the files, that contain the rules
		#sed 's/\[tag /\[Tags: /' "$TMP_FILE" | sed 's/\] \[tag / /g' | sed -r -n 's/^.*\[file "(.*)"\] \[line.*\[id "([0-9]+)".*$/\/\2; \1/p' | sort -u

	fi

	#echo '*** -------------'
	#cat "$TMP_FILE"
}

edit_rules_and_rload_apache2() {
	read -p "Press [Enter] to continue, press [Ctrl+C] to cancel..."
	cp "$MOD_SECURITY_WHITELIST_FILE"{,.bak}
	nano "$MOD_SECURITY_WHITELIST_FILE"
	systemctl reload apache2.service; echo; systemctl status apache2.service
}

debug_script_variables() {
	echo; echo -------------------; echo
	echo "REQEST URI:     $REQUEST_URI"
	echo "REQEST URI FLT: $REQUEST_URI_FILTRED"
	echo
	echo "UNIQUE_ID_PARS: $UNIQUE_ID_PARSED"
	echo
	echo "COOKIE:"
	echo "$COOKIE"
	echo; echo -------------------; echo
}

clear_temp_and_log() {
	rm -rf "$LOG_FILE" "$TMP_FILE"
}


# ---------------------------------
# The main script section
# ---------------------------------

if   [[ $ANALYSIS_TYPE == "latest-log" ]]
then
    sed -n '/-A--/h;//!H;$!d;x;//p' "$LOG_FILE" > "$TMP_FILE"
elif [[ $ANALYSIS_TYPE == "unique-id"  ]] && [[ ! -z ${UNIQUE_ID} ]] && [[ ${#UNIQUE_ID} -eq 27 ]]
then
    sed -n "/${UNIQUE_ID}/,$ p" "$LOG_FILE" | sed '/-Z--/,$d' > "$TMP_FILE"
else
    echo
    echo "## The correct syntax must be:"
    echo
    echo -e "\t modsecurity-white-list-rule-generator '999xxx' 'latest-log'\n"
    echo -e "\t modsecurity-white-list-rule-generator '999xxx' 'unique-id' '27-CharactersLong-UniqueID'\n"
    echo -e "\t Where '999xxx' is the number of the new rule. Use '999999' to parse and calculate the number automatically.'\n"
    exit 0
fi

get_info
#debug_script_variables

if [[ $RULE_NUMBER == 'active-rules' ]]
then
	active_rules
else
	head_message
	echo; echo -e "${YEL}"
	rule_number
	#rule_info
	#rule_body
	/usr/bin/php -r '$arg1 = $argv[1];echo rawurldecode($arg1);' "$(rule_info)"
        /usr/bin/php -r '$arg1 = $argv[1];echo rawurldecode($arg1);' "$(rule_body)"
	echo; echo -e "${NCL}"
	edit_rules_and_rload_apache2
	clear_temp_and_log
fi

exit 0


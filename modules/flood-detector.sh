#!/bin/bash -e

# Name:    modules/flood-detector.sh
# Summary: Custom script that analyse the output of 'netstat' for THRESHOLD number of 'SYN_RECV' (or any other) TCP states per IP/PORT, etc.
#          When a possible FLOOD Attack is detected it calls wwwsas.sh from the same packages.
#          The script is designed to be executed via CRON Job as well as SHELL Command.
# Home:    https://github.com/metalevel-tech/wwwsas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# Usage. The sctipt has two modes.
# Default mode, that will outut the result in CLI: './flood-detector.sh'
# AutoMode, that should be used in Root`s Crontab: '* * * * * "/path/to/flood-detector.sh" 'AutoMode' >> "/path/to/tmp/execution.log" 2>&1'


# -------------------------
# Read the user's input
# -------------------------

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }


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

TMP_FILE="${WWW_SAS_TMP}/flood-detector.tmp"


# ---------------------------------
# The main script section
# ---------------------------------

# Snapshot shooting the output of `netstat -tnupa`
/bin/netstat -tnupa > "$TMP_FILE"

# The main loop
for TCP_STATE in "${TCP_STATES[@]}"
do
	COMMON_CONNECTIONS_NUMBER="$(grep -c "$TCP_STATE" "$TMP_FILE")"
	if [[ $COMMON_CONNECTIONS_NUMBER -ge $COMMON_CONNECTIONS_THRESHOLD  ]]
	then
		#echo $COMMON_CONNECTIONS_NUMBER
		OUR_IPs=( $(grep "$TCP_STATE" "$TMP_FILE" | awk '{print $4}' | cut -d':' -f1 | sort -u) )
		#echo $OUR_IPs
		for OUR_IP in "${OUR_IPs[@]}"
		do
			#echo $OUR_IP
			OUR_PORTs=( $(grep "$TCP_STATE" "$TMP_FILE" | awk '{print $4}' | cut -d':' -f2 | sort -u) )
			#echo $OUR_PORTs
			for OUR_PORT in "${OUR_PORTs[@]}"
			do
				#echo $OUR_PORT
				ATTACKING_IPs=( $(grep "$TCP_STATE" "$TMP_FILE" | grep "$OUR_IP" | grep "$OUR_PORT" | awk '{print $5}' | cut -d':' -f1 | sort -u) )
				#echo $ATTACKING_IPs
				for ATTACKING_IP in "${ATTACKING_IPs[@]}"
				do
					#echo $ATTACKING_IP
					SINGLE_CONNECTIONS_NUMBER="$(grep "$TCP_STATE" "$TMP_FILE" | grep "$OUR_IP" | grep "$OUR_PORT" | grep -c "$ATTACKING_IP")"
					#echo $SINGLE_CONNECTIONS_NUMBER
					if [[ $SINGLE_CONNECTIONS_NUMBER -ge $SINGLE_CONNECTIONS_THRESHOLD  ]]
					then
						if [[ ${1} == 'AutoMode' ]]
						then
							# Compose the log note
							ATTACK_INFO="Attacking IP: ${ATTACKING_IP}${MY_DIVIDER}${TCP_STATE} count: ${SINGLE_CONNECTIONS_NUMBER}${MY_DIVIDER}On our IP/Port: ${OUR_IP} :${OUR_PORT}${MY_DIVIDER}"
							FLOODT_REPORT="${TCP_STATE} count: ${SINGLE_CONNECTIONS_NUMBER}"

							## Output a log header
							printf '\n\n*****\nSECURITY LOG from %s on %s : %s >>' "$TIME" "$DATE" "$WWW_SAS_FLOOD_DETECTOR_EXEC" >> "$WWW_SAS_EXEC_LOG" 2>&1
							# Call WWW Security Assistant Script
							exec "$WWW_SAS_EXEC" "$ATTACKING_IP" 'FloodDetector' "$ATTACK_INFO" "$FLOODT_REPORT" >> "$WWW_SAS_EXEC_LOG" 2>&1 &
						else
							printf '\n***\nFLOOD attack detected:\nFrom attacking IP: \t%s\n%s count: \t%s\nOn our IP/Port: \t%s :%s\n' "$ATTACKING_IP" "$TCP_STATE" "$SINGLE_CONNECTIONS_NUMBER" "$OUR_IP" "$OUR_PORT"
						fi
					fi
				done
			done
		done
	fi
done

exit 0

#!/bin/bash -e

# Name: www-security-assistant.bash [default work directory /var/www-security-assistant]
# Summary: Custom script designed to help you with malicious IP addresses handling.
#          The IPs should be provided by external programs 
#          such as ModSecurity or ModEvasive for Apache web server.
# Home: https://github.com/pa4080/security-assistant
# Author: Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2018
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.

# The script should be run as root
[[ "$EUID" -ne 0 ]] && { echo "Please run as root (use sudo)."; exit 0; }

# Check the dependencies
[[ -x /usr/bin/at ]] || { echo "Please, install 'at'"; exit 0; }
[[ -x /usr/bin/tee ]] || { echo "Please, install 'tee'"; exit 0; }
[[ -x /usr/bin/awk ]] || { echo "Please, install 'awk'"; exit 0; }
[[ -x /usr/bin/who ]] || { echo "Please, install 'who'"; exit 0; }
[[ -x /usr/bin/mail ]] || { echo "Please, install 'mail' command"; exit 0; }
[[ -x /sbin/iptables ]] || { echo "Please, install 'iptables'"; exit 0; }

# Check the input data
[[ -z ${1+x} ]] || [[ -z ${2+x} ]] && (echo "$USAGE"; echo; exit 0)

# Get the time coordinates of the event
TIME="$(date +%H:%M:%S)"
DATE="$(date +%Y-%m-%d)"

# Asign the input data to certain variables
IP="${1}"     # IP address - the first argument
AGENT="${2}"  # MODE or AGENT; Automatic MODE, available agents: [ ModSecurity | ModEvasive | Guardian | a2Analyst ]; Only ModSecurity uses $NOTES
NOTES="${3}"  #                Manual MODE:                      [ --DROP "$NOTES" | --DROP-CLEAR "$NOTES" | --ACCEPT "$NOTES" | --ACCEPT-CHAIN "$NOTES" ]

# Get the $USER that execute the script
RUN_USER="$(who am i | awk '{print $1}')"
if [[ -z ${RUN_USER} ]]; then RUN_USER="$USER"; fi
if [[ -z ${RUN_USER} ]]; then RUN_USER="root"; fi

## OPTIONS
WORK_DIR="/var/www-security-assistant"               # The directory where the script is placed; WORK_DIR="$(dirname ${0})" - makes problems
HOSTNAME=$(hostname -f)                              # Get server's host-name (https://unix.stackexchange.com/a/51987/201297)

WHITE_LIST="$WORK_DIR/iptables-ACCEPT.list"          # White-list at least your server's IP and localhost IP 127.0.0.1
BAN_LIST="$WORK_DIR/iptables-DROP.list"
BAN_CLEAR_LIST="$WORK_DIR/iptables-DROP-CLEAR.list"
HISTORY="$WORK_DIR/www-security-assistant.history"   # Please be careful when manipulate this file manually

APACHE_LOG="/var/log/apache2"                        # The log directory mentioned in /etc/apache2/envvars
EVASIVE_LOG="/var/log/apache2_mod_evasive"           # The log directory mentioned in /etc/apache2/mod-available/evasive.conf
SECURITY_LOG="/var/log/apache2_mod_security2"        # The log directory mentioned in /etc/apache2/mods-available/security2.conf or /etc/modsecurity/modsecurity.conf

EMAIL_BODY="$WORK_DIR/www-security-assistant.mail"   # This file will exists until next thread
EMAIL_FROM="Security Assistant <root@$HOSTNAME>"     # Or just enter <your@email.foo>
EMAIL_TO="$RUN_USER@$HOSTNAME"                       # Multiple accounts separated by commas: EMAIL_TO="your@email.foo, your@email.bar, your@email.baz"

IPTABLES_SAVE="$WORK_DIR/iptables-save.sh"           # Here is used additional script as iptables save command: https://www.cyberciti.biz/faq/iptables-read-and-block-ips-subnets-from-text-file/
                                                     # It can be replaced with something as its content: iptables-save > /var/www-security-assistant/iptables-CURRENT.conf

BAN_TIME="5 minutes"                                 # Time-units can be minutes, hours, days, or weeks; see `man at`; `sudo atq` lists pending jobs; `sudo at -c job_number` shows the job's content;
LIMIT="10"                                           # Limit of tolerance of transgressions from certain IP

MY_DIVIDER='-DiViDeR-d1v1d3r-'                       # This step solves an old issue and it is not longer needed - but why not :)

# Set the list of the available Agents in tha Automatic mode
AGENTS=("Guardian" "ModSecurity" "ModEvasive" "a2Analyst")

# Set the content of the frequent used messages, touch some files with attention to create them in case they do not exist
USAGE="Usage: <IP> [ ModSecurity | ModEvasive | Guardian | a2Analyst ] or [ --DROP 'log notes' | --DROP-CLEAR 'log notes' | --ACCEPT 'log notes' | --ACCEPT-CHAIN 'log notes' ]"
UNBLOCK="Unblock: sudo iptables -D GUARDIAN -s $IP -j DROP | sudo www-security-assistant.bash $IP --DROP-CLEAR 'log notes'" 
touch "$HISTORY" "$WHITE_LIST" "$BAN_LIST" "$BAN_CLEAR_LIST"

# Output a header for the log file
printf "\n\n***** SECURITY LOG from %s on %s : www-security-assistant.bash : %s : %s\n\n" "$TIME" "$DATE" "$AGENT" "$IP"

## The ACTION SECTION

# If the $IP is a member of the $WHITE_LIST
if [[ ! -z $(grep -o "$IP" "$WHITE_LIST") ]]; then

    # Output a message and exit
    printf 'The IP address %s is a member of the Withe List!\n\n' "$IP"
    exit 0

# Add $IP to the DROP (BAN) List, syntax: www-security-assistant.bash <IP> --DROP 'log notes'"
elif [ "$AGENT" == "--DROP" ]; then

    iptables -A GUARDIAN -s "$IP" -j DROP
    iptables -L GUARDIAN -n --line-numbers
    eval "$IPTABLES_SAVE"
    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was added to the DROP (BAN) List by @%s: %-18s \t| Notes: %s %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" "$UNBLOCK" | tee -a "$BAN_LIST"
    exit 0

# Remove $IP from the DROP (BAN) List, syntax: www-security-assistant.bash <IP> --DROP-CLEAR 'log notes'"
elif [ "$AGENT" == "--DROP-CLEAR" ]; then

    iptables -L GUARDIAN -n --line-numbers; echo
    sed -i "/$IP/d" $HISTORY
    sed -i "/$IP/d" $BAN_LIST
    iptables -D GUARDIAN -s "$IP" -j DROP
    eval "$IPTABLES_SAVE"; echo 
    iptables -L GUARDIAN -n --line-numbers; echo
    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was removed from the DROP (BAN) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" | tee -a "$BAN_CLEAR_LIST"
    exit 0

# Add $IP to the ACCEPT (WHITE) List, syntax: www-security-assistant.bash <IP> --ACCEPT 'log notes'"
elif [ "$AGENT" == "--ACCEPT" ]; then

    # Output and Log a message and exit
    printf 'On %-10s at %-8s | This IP/CIDR was added to the ACCEPT (WHITE) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" | tee -a "$WHITE_LIST"
    exit 0

# Add $IP to the ACCEPT (WHITE) List and add Iptables rule, syntax: www-security-assistant.bash <IP> --ACCEPT-CHAIN 'log notes'"
elif [ "$AGENT" == "--ACCEPT-CHAIN" ]; then

    iptables -A GUARDIAN -s "$IP" -j ACCEPT
    iptables -L GUARDIAN -n --line-numbers
    eval "$IPTABLES_SAVE"
    # Output and Log a message and exit
    NOTE='Iptables rule has been created!'
    printf 'On %-10s at %-8s | This IP/CIDR was added to the ACCEPT (WHITE) List by @%s: %-18s \t| Notes: %s %s\n' "$DATE" "$TIME" "$RUN_USER" "$IP" "$NOTES" "$NOTE" | tee -a "$WHITE_LIST"
    exit 0

# If the $AGENT belogs to the list of $AGENTS
elif [[ " ${AGENTS[@]} " == *" ${AGENT} "* ]]; then
    # Get the number of the previous transgressions from this $IP and increment +1 to get the current number; 
    # Note `$(grep -c $IP $HISTORY)` sometimes works sometime doesn't work.
    IP_SINS=$(cat "$HISTORY" | grep "$IP" | wc -l); IP_SINS=$((IP_SINS+1))

    if [ ! "$IP_SINS" -ge "$LIMIT" ]; then

        # Add the following firewall rule (block IP); alt.: `iptables -I INPUT -p tcp --dport 80 -s %s -j DROP`
        iptables -I GUARDIAN -s "$IP" -j DROP
        # Unblock offending IP after $BAN_TIME through the `at` command
        echo "iptables -D GUARDIAN -w -s \"$IP\" -j DROP && $IPTABLES_SAVE" | at now + "$BAN_TIME"
        # GO FORWARD

    else

        # Add $IP to the Black List add Iptales rule. Please note that
        # The $NOTES are not logged here, this will be done within the following section: Log the current thread
        iptables -A GUARDIAN -s "$IP" -j DROP
        eval "$IPTABLES_SAVE"
        printf 'On %-10s at %-8s | This IP/CIDR was added to the DROP (BAN) List by @%s: %-18s \t| Notes: %s\n' "$DATE" "$TIME" "$AGENT" "$IP" "$UNBLOCK" | tee -a "$BAN_LIST"
        # GO FORWARD

    fi

else

    echo "Something went wrong!"; echo; echo "$USAGE"; echo;
    exit 0

fi


## Prepare the notes that comes from modsecurity-assistant.sh
## The custom divider is used to dicourage some bug when the note comes from ModSecurity
NOTES_LOCAL="$(echo "$NOTES" | sed -e "s/$MY_DIVIDER/; /g")"
NOTES_EMAIL="$(echo "$NOTES" | sed -e "s/$MY_DIVIDER/\n/g")"

## Log the current thread into the $HISTORY file
printf 'On %-10s at %-8s | %-12s : %-18s | Notes: %s\n' "$DATE" "$TIME" "$AGENT" "$IP" "$NOTES_LOCAL" | tee -a "$HISTORY"

## The Construct E-MAIL SECTION

    printf '\n---===| %s Security Assistant |===---\n' "${HOSTNAME^^}" > $EMAIL_BODY
    printf '\n%s:\n' "$AGENT" >> $EMAIL_BODY
if [[ $AGENT == "ModSecurity" ]]; then
    printf '\nNew transgression has been detected from this source IP address: %s\n\n' "$IP" >> $EMAIL_BODY
    echo "${NOTES_EMAIL}" >> $EMAIL_BODY
else
    printf '\nMassive connections has been detected from this source IP address: %s\n' "$IP" >> $EMAIL_BODY
fi
    printf '\nThe current number of committed transgressions from this IP is %s.\n' "$IP_SINS" >> $EMAIL_BODY
if [ ! "$IP_SINS" -ge "$LIMIT" ]; then
    printf '\nThe system has blocked the IP in the firewall for %s as from %s on %s.\n' "$BAN_TIME" "$TIME" "$DATE" >> $EMAIL_BODY
else
    printf '\nThey reached our Limit of tolerance, currently equal to %s transgressions, and were added to the BAN List!\n' "$LIMIT" >> $EMAIL_BODY
    printf '\n<!-- WHOIS %s report begin:\n\n' "$IP" >> $EMAIL_BODY; whois "$IP" >> "$EMAIL_BODY"; printf '\nWHOIS %s report end. -->\n' "$IP" >> "$EMAIL_BODY"
fi
    printf '\nTo allow access to this IP address manually: %s \n' "$UNBLOCK" >> $EMAIL_BODY
    printf '\n---===| %s Security Assistant |===---\n' "${HOSTNAME^^}" >> $EMAIL_BODY

# Send the E-MAIL
cat "$EMAIL_BODY" | mail -r "$EMAIL_FROM" -s "Attack Detected - ${HOSTNAME^^}" "$EMAIL_TO"

# Remove ModEvasive lock file for future checks
if [ "$AGENT" == "ModEvasive" ]; then rm -f "$EVASIVE_LOG/dos-$IP"; fi

# Add clarification to the copy of the last sent email
printf '\n***\n This email has been sent to %s at %s\n\n' "$EMAIL_TO" "$TIME" >> $EMAIL_BODY

exit 0
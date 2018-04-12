#!/bin/bash -e

# Name: security-assistant.bash [default work folder /var/www-security, for more details see the bottom of the file]
# Summary: Custom script designed to helps you with malicious IP addresses handling
# Manual: https://askubuntu.com/a/922144/566421
# Author: Spas Z. Spasov <spas.z.spasov@gmail.com> 21.06.2017
# Download command: curl https://pastebin.com/raw/wvV9B1nf | sed -e 's/\r$//' | sudo tee /var/www-security/security-assistant.bash

TIME="$(date +%H:%M:%S)"                                        			       # Get the current time
DATE="$(date +%Y-%m-%d)"                                        			       # Get the current date
printf "\n\n***** SECURITY LOG from $TIME on $DATE - security-assistant.bash : $2 : $1\n\n"    # Echo a header for the log file

		#LOG:
		echo "$IP"
		echo "security-assistant.bash S1"

[ -z "${1+x}" ] || [ -z "${2+x}" ] && (echo "Usage: <IP> [ ModSecurity | ModEvasive | Guardian | a2Analyst ] or [ --DROP \"log note\" | --DROP-CLEAR \"log note\" | --ACCEPT \"log note\" | --ACCEPT-CHAIN \"log note\" ]"; echo; exit 1)
[ -x /usr/bin/at ] || (echo "Please, install 'at'"; exit 1)

## OPTIONS
		#LOG:
		echo "security-assistant.bash S2"

IP="$1"                                                         # IP address - the first argument
AGENT="$2"                                                      # MODE or AGENT; Automatic MODE, available agents: [ ModSecurity | ModEvasive | Guardian | a2Analyst ]; Or Manual MODE: [ --DROP | --ACCEPT "log note" | --ACCEPT-CHAIN "log note" ]
NOTES="$3"                                                      # "$NOTES" ("$3") can be used when [ "$2" == "--ACCEPT" ]; or when 'ModSecurity' is engaged

WORK_DIR="/var/www-security"                                    # In the Automatic MODE, where the script is called by absolute path, next shall works properly: WORK_DIR=$(pwd); echo $WORK_DIR
HOSTNAME=$(/bin/hostname -f)                                    # Get server's host-name (https://unix.stackexchange.com/a/51987/201297)

WHITE_LIST="$WORK_DIR/iptables-ACCEPT.list"                     # White-list at least your server's IP and localhost IP 127.0.0.1
BAN_LIST="$WORK_DIR/iptables-DROP.list"
BAN_CLEAR_LIST="$WORK_DIR/iptables-DROP-CLEAR.list"
hCACHE="$WORK_DIR/security-assistant.history"                   # Please be careful when manipulate this file manually

APACHE_LOG="/var/log/apache2"                                   # The log directory mentioned in /etc/apache2/envvars
EVASIVE_LOG="$APACHE_LOG/mod_evasive"                           # The log directory mentioned in /etc/apache2/mod-available/evasive.conf
SECURITY_LOG="$APACHE_LOG/mod_security2"                        # The log directory mentioned in /etc/apache2/mods-available/security2.conf or /etc/modsecurity/modsecurity.conf

EMAIL_BODY="$WORK_DIR/security-assistant.mail"                  # This file will exists until next thread
EMAIL_FROM="Security Assistant <root@$HOSTNAME>"                # Or just enter <your@email.foo>
#EMAIL_TO="admin@$HOSTNAME, user@$HOSTNAME"                     # Multiple accounts separated by commas: EMAIL_TO="your@email.foo, your@email.bar, your@email.baz"
EMAIL_TO="szs.wiki.mailer@gmail.com, trivium@$HOSTNAME"         # Multiple accounts separated by commas: EMAIL_TO="your@email.foo, your@email.bar, your@email.baz"

IPTABLES_SAVE="$WORK_DIR/iptables-save.sh"                      # Here is used additional script as iptables save command: https://www.cyberciti.biz/faq/iptables-read-and-block-ips-subnets-from-text-file/
                                                                # It can be replaced with something as its content: /sbin/iptables-save > /var/www-security/iptables-CURRENT.conf

BAN_TIME="5 minutes"                                            # Time-units can be minutes, hours, days, or weeks; see `man at`; `sudo atq` lists pending jobs; `sudo at -c job_number` shows the job's content;
LIMIT="3"                                                       # Limit of tolerance of transgressions from certain IP

## Create Actions
## BEGIN:: If the $IP is not in the $WHITE_LIST check current mode: MANUAL add IP to ACCEPT/DROP List; AUTOMATIC detect $AGENT, GOTO action and log $IP in $hCACHE

		#LOG:
		echo "security-assistant.bash S3"

if [ ! "$(grep "$IP" "$WHITE_LIST")" == "" ]; then

                echo "The IP address $IP is a member of the Withe List!"; echo;

                exit 1

elif [ "$AGENT" == "--DROP" ]; then             # Add $IP to the DROP (BAN) List, syntax: ./security.bash 192.168.1.222 "--DROP"

                /sbin/iptables -A GUARDIAN -s $IP -j DROP
                /sbin/iptables -L GUARDIAN -n --line-numbers

                eval "$IPTABLES_SAVE"           # https://unix.stackexchange.com/a/23116/201297 , https://unix.stackexchange.com/a/296852/201297

		printf "%-46s %-16s %s %-14s %-72s %s\n" "On $DATE at $TIME - This IP or CIDR:" "$IP" "was added to the DROP (BAN) List by" "the Admin." "Unblock command: sudo iptables -D GUARDIAN -s $IP -j DROP" "Notes: $NOTES" | /usr/bin/tee -a "$BAN_LIST"

                exit 1

elif [ "$AGENT" == "--DROP-CLEAR" ]; then       # Add $IP to the DROP (BAN) List, syntax: ./security.bash 192.168.1.222 "--DROP-CLEAR"

                /sbin/iptables -L GUARDIAN -n --line-numbers
		echo

                printf "%-46s %-16s %s %-14s %s\n" "On $DATE at $TIME - This IP or CIDR:" "$IP" "was cleared from the DROP (BAN) List by" "the Admin." "Notes: $NOTES" | /usr/bin/tee -a "$BAN_CLEAR_LIST"

		sed -i "/$IP/d" $hCACHE
		sed -i "/$IP/d" $BAN_LIST
		/sbin/iptables -D GUARDIAN -s $IP -j DROP

                eval "$IPTABLES_SAVE"           # https://unix.stackexchange.com/a/23116/201297 , https://unix.stackexchange.com/a/296852/201297

		echo
		/sbin/iptables -L GUARDIAN -n --line-numbers
                echo

                exit 1

elif [ "$AGENT" == "--ACCEPT" ]; then           # Add $IP to the ACCEPT (WHITE) List, syntax: ./security.bash 192.168.1.222 "--ACCEPT" "My home machine."

                printf "%-46s %-16s %s %-14s %s\n" "On $DATE at $TIME - This IP or CIDR:" "$IP" "was added to the ACCEPT (WHITE) List by" "the Admin." "Notes: $NOTES" | /usr/bin/tee -a "$WHITE_LIST"

                exit 1

elif [ "$AGENT" == "--ACCEPT-CHAIN" ]; then     # Add $IP to the ACCEPT (WHITE) List, syntax: ./security.bash 192.168.1.222 "--ACCEPT" "My home machine."

                /sbin/iptables -A GUARDIAN -s $IP -j ACCEPT
                /sbin/iptables -L GUARDIAN -n --line-numbers

                eval "$IPTABLES_SAVE"                                                                                                  # https://unix.stackexchange.com/a/23116/201297 , https://unix.stackexchange.com/a/296852/201297

                printf "%-46s %-16s %s %-14s %s\n" "On $DATE at $TIME - This IP or CIDR:" "$IP" "was added to the ACCEPT (WHITE) List by" "the Admin." "Notes: $NOTES | Iptables rule has been created!" | /usr/bin/tee -a "$WHITE_LIST"

                exit 1

elif [ "$AGENT" == "Guardian" ] || [ "$AGENT" == "ModSecurity" ] || [ "$AGENT" == "ModEvasive" ] || [ "$AGENT" == "a2Analyst" ]; then  # If $AGENT has a valid value - do some things and go further

		#LOG:
		echo "security-assistant.bash S4"

		IP_SINS=$(cat $hCACHE | grep $IP | wc -l)	# Number of the previous transgressions from this $IP # IP_SINS="$(grep -c ${IP} ${hCACHE})" - sometimes works sometime doesn't work
		IP_SINS=$((IP_SINS+1))				# Number of the current transgressions from this $IP  # https://askubuntu.com/questions/385528/how-to-increment-a-variable-in-bash

	   	#LOG:
		echo "security-assistant.bash S5"

	if [ ! "$IP_SINS" -ge "$LIMIT" ]; then

      	        /sbin/iptables -I GUARDIAN -s $IP -j DROP       # Add the following firewall rule (block IP); alt.: `/sbin/iptables -I INPUT -p tcp --dport 80 -s %s -j DROP`
								# Unblock offending IP after $BAN_TIME through the `at` command
              	echo "/sbin/iptables -D GUARDIAN -w -s $IP -j DROP && $(echo "$IPTABLES_SAVE")" | /usr/bin/at now + $BAN_TIME

		#LOG:
		echo "security-assistant.bash S6"

	else

               	/sbin/iptables -A GUARDIAN -s $IP -j DROP       # Add $IP to the Black List, more complicated script:
                eval "$IPTABLES_SAVE"                           # https://unix.stackexchange.com/a/23116/201297 , https://unix.stackexchange.com/a/296852/201297

		printf "%-46s %-16s %s %-14s %s\n" "On $DATE at $TIME - This IP or CIDR:" "$IP" "was added to the DROP (BAN) List by" "$AGENT." "Unblock command: sudo iptables -D GUARDIAN -s $IP -j DROP" | /usr/bin/tee -a "$BAN_LIST"

		#LOG:
		echo "security-assistant.bash S7"

	fi

else 		# Else something is not correct

		echo "Usage: <IP> [ ModSecurity | ModEvasive | Guardian | a2Analyst ] or [ --DROP \"log note\" | --DROP-CLEAR \"log note\" | --ACCEPT \"log note\" | --ACCEPT-CHAIN \"log note\" ]"; echo;

                exit 1

fi

## Log the current thread

		#LOG:
		echo "security-assistant.bash S8"

NOTES_="$(echo "$NOTES" | sed -e 's/-DiViDeR-d1v1d3r-/; /g')"
printf "%s %-14s %-16s %s\n" "On $DATE at $TIME -" "$AGENT:" "$IP" "Notes: ${NOTES_}" >> "$hCACHE"

## Construct E-MAIL
echo "security-assistant.bash S9"

                printf "\n---===| ${HOSTNAME^^} Security Assistant |===---\n" > $EMAIL_BODY
                printf "\n$AGENT:\n" >> $EMAIL_BODY
if [ "$AGENT" == "ModSecurity" ]; then
                printf "\nNew transgression has been detected from this source IP address: $IP\n\n" >> $EMAIL_BODY
                echo "${NOTES}" | sed -e 's/-DiViDeR-d1v1d3r-/\n/g' >> $EMAIL_BODY
else
                printf "\nMassive connections has been detected from this source IP address: $IP\n" >> $EMAIL_BODY
fi
                printf "\nThe current number of committed transgressions from this IP is $IP_SINS.\n" >> $EMAIL_BODY
if [ ! "$IP_SINS" -ge "$LIMIT" ]; then
                printf "\nThe system has blocked the IP in the firewall for $BAN_TIME as from $TIME on $DATE.\n" >> $EMAIL_BODY
else
                printf "\nThey reached our Limit of tolerance, currently equal to $LIMIT transgressions, and were added to the BAN List!\n" >> $EMAIL_BODY
                printf "\n<!-- WHOIS $IP report begin:\n\n" >> $EMAIL_BODY; echo "$(whois $IP)" >> $EMAIL_BODY; printf "\nWHOIS $IP report end. -->\n" >> $EMAIL_BODY
fi
                printf "\nTo allow access to this IP address manually - run: sudo iptables -D GUARDIAN -s $IP -j DROP\n" >> $EMAIL_BODY
                printf "\n---===| ${HOSTNAME^^} Security Assistant |===---\n" >> $EMAIL_BODY


# Send E-MAIL notification

		#LOG:
		echo "security-assistant.bash S10"

cat $EMAIL_BODY | /usr/bin/mail -r "$EMAIL_FROM" -s "Attack Detected - ${HOSTNAME^^}" $EMAIL_TO


# Remove lock file for future checks

		#LOG:
		echo "security-assistant.bash S11"

if [ "$AGENT" == "ModEvasive" ]; then
        rm -f "$EVASIVE_LOG/dos-$IP"
fi


# Add clarification to the copy of the last sent email

		#LOG:
		echo "security-assistant.bash S12"

printf "\n***\n This email has been sent to $EMAIL_TO at $TIME\n\n" >> $EMAIL_BODY

exit 1

# Basic System  Configuration:
#
# * Default script location '/var/www-security'
#
# * Custom Iptables chain is used: 'sudo iptables -N GUARDIAN; sudo iptables -I INPUT -j GUARDIAN'
#
# * Create log file: sudo touch /var/www-security/security-assistant.bash-exec.log && sudo chown www-data:www-data /var/www-security/security-assistant.bash-exec.log

# * Grand sudo permissions to 'www-data' for the script:
#               type 'sudo visudo' and add this line:
#               www-data ALL=(ALL) NOPASSWD: /var/www-security/security-assistant.bash
#
# * To call the script via 'ModEvasive' edit '/etc/apache2/mods-available/evasive.conf' and add or change next directive:
#               DOSSystemCommand    "sudo /var/www-security/security-assistant.bash %s 'ModEvasive' >> /var/www-security/security-assistant-exec.log 2>&1"
#
# * To call the script via 'httpd-guardian' (http://apache-tools.cvs.sourceforge.net/viewvc/apache-tools/apache-tools/httpd-guardian?revision=1.6) add or change this directive:
#               my $PROTECT_EXEC = "exec /var/www-security/security-assistant.bash %s 'Guardian' >> /var/www-security/security-assistant-exec.log 2>&1";
#
# * How to call the script via the script 'apache-log-analyst.bash' (https://pastebin.com/k4ejvc81) is explanes in its body.
#
# * To call the script via 'ModSecurity' - we must create simple call script and custom ModSecRule:
#
#     * create simple call script, and grand executable permissions to all, because of 'www-data' (https://pastebin.com/ChgLncLH):
#               printf '#!/bin/sh\nsudo /var/www-security/security-assistant.bash $REMOTE_ADDR 'ModSecurity'\n' | sudo tee /var/www-security/security-assistant-modsec.sh && sudo chmod a+rx /var/www-security/security-assistant-modsec.sh
#
#     * example of custom ModSecRule, for example when you don`t have Joomla installed but hackers try to find security holes in it (see your apache`s log):
#               SecRule REQUEST_URI "^/joomla" "id:665544,deny,t:lowercase,setenv:REMOTEIP=%{REMOTE_ADDR},setenv:REQUESTURI=%{REQUEST_URI},exec:/var/www-security/security-assistant-modsec.sh"

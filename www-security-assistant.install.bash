#!/bin/bash

# List of the files to be downloaded
SOURCE_FILES=()
SOURCE_FILES+=('www-security-assistant.bash')
SOURCE_FILES+=('httpd-guardian.pl')
SOURCE_FILES+=('httpd-custom-analyze.bash')
SOURCE_FILES+=('modsecurity-assistant.sh')
SOURCE_FILES+=('iptables-save.sh')
SOURCE_FILES+=('iptables-restore.sh')
SOURCE_FILES+=('modsecurity-uri-black.list.example')
SOURCE_FILES+=('modsecurity-ip-white.list.example')
SOURCE_FILES+=('www-security-assistant.conf.example')

# List of brances that this script can handle
AVAILABLE_BRANCHES=("stable.v.1")

# Temporary file used for the comparison by '$DIFF'
TEMP_FILE='/tmp/www-security-assistant.tmp'

# The script should be executed as root (use sudo)
if [[ ! $USER == 'root' ]]; then echo "You should run this script as root. Use sudo."; exit 0; fi

# Output colors
RED='\033[0;31m'
GRE='\033[0;32m'
YEL='\033[1;33m'
NCL='\033[0m'   # No color

# Compose the DIFF command
if   [[ -f /usr/bin/colordiff ]]; then DIFF='/usr/bin/colordiff -c'
elif [[ -f /usr/bin/diff ]]; then DIFF='/usr/bin/diff -c'; echo -e "For better file comparison use 'colordiff':\n\tsudo apt install colordiff\n"
else echo -e "This installer uses 'diff' or 'colordiff' please make sure some of them is installed.\n"; exit 0
fi

# Get the target branch
echo
read -p "$(echo -e "Press Enter to download from the ${YEL}master${NCL} branch or type the name of another target branch [ $(printf "${GRE}%s${NCL} | " "${AVAILABLE_BRANCHES[@]}" | sed 's/...$//') ]: ")" BRANCH
if [[ -z ${BRANCH} ]]; then BRANCH="${AVAILABLE_BRANCHES[0]}"; fi

# Compose and output the base URL of the target branch
BASE_URL="https://raw.githubusercontent.com/pa4080/www-security-assistant/${BRANCH}"
echo -e "\nBase URL: \t${YEL}${BASE_URL}${NCL}\n\n"

# Compose and output the base URL of the target branch
read -p "$(echo -e "Press Enter to download into the default directory ${YEL}/var/www-security-assistant${NCL} or type the name of another directory: ")" WORK_DIR
if [[ -z ${WORK_DIR} ]]; then WORK_DIR='/var/www-security-assistant'; fi
if [[ ! -d ${WORK_DIR} ]]
then
    read -p "This directory doesn't exist. Do you want to create it?  [Yes/No] Default [Yes]: " CONFIRM
    if [[ -z ${CONFIRM} ]]; then CONFIRM='Yes'; fi 
    if [[ $CONFIRM == [yY] || $CONFIRM == [yY][eE][sS] ]]; then mkdir -p "$WORK_DIR" || exit 0 && echo "Done."; else exit 0; fi
fi
echo -e "\nWork directory: ${YEL}${WORK_DIR}${NCL}"

# This is the actual installation dialogue that is executed for each file
installation_dialogue() {
    if [[ -f $TARGET_FILE ]]
    then
        eval "$DIFF" "$TARGET_FILE" "$TEMP_FILE"
        if [[ -z $(eval "$DIFF" "$TARGET_FILE" "$TEMP_FILE") ]]
        then echo -e "\n${GRE}## There is no difference between ${YEL}$TARGET_FILE${NCL} ${GRE}and ${YEL}${BRANCH}/${SOURCE_FILE}${NCL}"
        else echo -e "\n${GRE}## The above is the result of:${NCL} ${YEL}$DIFF $TARGET_FILE ${BRANCH}/${SOURCE_FILE}${NCL}"
        fi
        DEFAULT_CONFIRM='No'
        QUESTION="\n${RED}Do you want to override ${YEL}${TARGET_FILE}${RED} ?${NCL} [Yes/No] Default [$DEFAULT_CONFIRM]:"
    else
        DEFAULT_CONFIRM='Yes'
        QUESTION="\n${GRE}Do you want to create ${YEL}${TARGET_FILE} ${GRE}?${NCL} [Yes/No] Default [$DEFAULT_CONFIRM]:"
    fi

    read -p "$(echo -e "${QUESTION}") " CONFIRM
    if [[ -z ${CONFIRM} ]]; then CONFIRM="$DEFAULT_CONFIRM"; fi

    echo -ne "${CONFIRM^}. "

    if [[ $CONFIRM == [yY] || $CONFIRM == [yY][eE][sS] ]]
    then
        [[ -f $TARGET_FILE ]] && cp "${TARGET_FILE}"{,.bak} && echo -n "A backup file was created. "
        cp "$TEMP_FILE" "$TARGET_FILE" && echo "Done."
    else
        echo -e "Skipped."
    fi
}

# The main installation loop begin
echo -e "\n\n\n\n\n${GRE}##### INSTALLATION BEGIN -----${NCL}"
for SOURCE_FILE in "${SOURCE_FILES[@]}"
do
    SOURCE_URL="${BASE_URL}/${SOURCE_FILE}"
    TARGET_FILE="${WORK_DIR}/${SOURCE_FILE}"
    printf "\n\n${GRE}##### %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue
    if [[ ${SOURCE_FILE} != *"example"* ]]
    then
        chmod +x "${TARGET_FILE}"
    fi
done

# Handle the example files
echo -e "\n\n\n\n\n${GRE}##### CUSTOMISATION BEGIN -----${NCL}"
for EXAMPLE_FILE in "${WORK_DIR}/"*'.example'
do
    TARGET_FILE="${EXAMPLE_FILE/\.example/}"
    TEMP_FILE="${EXAMPLE_FILE}"
    printf "\n\n${GRE}##### %s${NCL} \n\nExample file:\t${YEL}%s${NCL}\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${EXAMPLE_FILE}" "${EXAMPLE_FILE}" "${TARGET_FILE}"
    installation_dialogue
done
echo -e "\n${RED}PLEASE MAKE SURE www-security-assistant.conf CORESPONDENT TO THE VERSION OF www-security-assistant.conf.example !!!${NCL}"

# Download the license file of the bundle
LICENSE='LICENSE'
LICENSE_FILE="${WORK_DIR}/${LICENSE}"
LICENSED_FILE="${WORK_DIR}/www-security-assistant.bash"
if [[ ! -f $LICENSE_FILE ]] && [[ -f $LICENSED_FILE ]]
then wget -q "${BASE_URL}/${LICENSE}" -O "${LICENSE_FILE}"
fi

# Download the license file of httpd-guardian.pl
LICENSE='httpd-guardian.GPLv2.license'
LICENSE_FILE="${WORK_DIR}/${LICENSE}"
LICENSED_FILE="${WORK_DIR}/httpd-guardian.pl"
if [[ ! -f $LICENSE_FILE ]] && [[ -f $LICENSED_FILE ]]
then wget -q "${BASE_URL}/${LICENSE}" -O "${LICENSE_FILE}"
fi

# Syatem Setup
echo -e "\n\n\n\n\n${GRE}##### System Setup BEGIN -----${NCL}"

rm /usr/local/bin/www-security-assistant.bash >/dev/null 2>&1
ln -s "${WORK_DIR}/www-security-assistant.bash" /usr/local/bin/
echo -ne "\n\n${GRE}## The file: ${YEL}/usr/local/bin/www-security-assistant.bash${NCL} is created!\n"

touch "${WORK_DIR}/www-security-assistant.execlog"
chown www-data "${WORK_DIR}/www-security-assistant.execlog"
echo -ne "\n\n${GRE}## The file: ${YEL}${WORK_DIR}/www-security-assistant.execlog${NCL} is created!\n"

echo 'www-data ALL=(ALL) NOPASSWD: /var/www-security-assistant/www-security-assistant.bash' > '/etc/sudoers.d/www-security-assistant'
echo -ne "\n\n${GRE}## The file: ${YEL}/etc/sudoers.d/www-security-assistant${NCL} is created!\n"

# Apache Modusles to be INSTALLED
APACHE_MODULES=("security2" "evasive")
echo -e "\n\n${GRE}## Apache Modusles Installation BEGIN -----${NCL}"
for MODULE in "${APACHE_MODULES[@]}"
do
    if apache2ctl -M | grep -q "$MODULE"
    then
        echo -e "\n${GRE}The ${YEL}${MODULE}${GRE} is already installed.${NCL}" 
    else 
        DEFAULT_CONFIRM='Yes'
        QUESTION="\n${GRE}Do you want to install ${YEL}libapache2-mod-${MODULE}${GRE} ?${NCL} [Yes/No] Default [$DEFAULT_CONFIRM]:"
        read -p "$(echo -e "${QUESTION}") " CONFIRM
        if [[ -z ${CONFIRM} ]]; then CONFIRM="$DEFAULT_CONFIRM"; fi

        echo -ne "${CONFIRM^}. "

        if [[ $CONFIRM == [yY] || $CONFIRM == [yY][eE][sS] ]]
        then
            apt install -y "libapache2-mod-${MODULE}"
        else
            echo -e "Skipped."
        fi
    fi
done

# Apache Modusles to be ENABLED
APACHE_MODULES=("security2" "evasive" "headers" "rewrite" "ssl" "dav_fs" "expires" "ext_filter")
for MODULE in "${APACHE_MODULES[@]}"
do
    if apache2ctl -M | grep -q "$MODULE"
    then
        echo -e "\n${GRE}The ${YEL}${MODULE}${GRE} is already enabled.${NCL}" 
    else 
        DEFAULT_CONFIRM='Yes'
        QUESTION="\n${GRE}Do you want to enable ${YEL}${MODULE}${GRE} ?${NCL} [Yes/No] Default [$DEFAULT_CONFIRM]:"
        read -p "$(echo -e "${QUESTION}") " CONFIRM
        if [[ -z ${CONFIRM} ]]; then CONFIRM="$DEFAULT_CONFIRM"; fi

        echo -ne "${CONFIRM^}. "

        if [[ $CONFIRM == [yY] || $CONFIRM == [yY][eE][sS] ]]
        then
            a2enmod "${MODULE}"
        else
            echo -e "Skipped."
        fi
    fi
done

# Mod Evasive Setup
if apache2ctl -M | grep -q "evasive"
then
    echo -e "\n\n${GRE}## Mod Evasive setup BEGIN -----${NCL}"

    mkdir -p /var/log/apache2_mod_evasive >/dev/null 2>&1
    chown www-data /var/log/apache2_mod_evasive
    echo -e "\n${GRE}The directory ${YEL}/var/log/apache2_mod_evasive${GRE} is created.${NCL}" 

    TEMP_FILE='/tmp/www-security-assistant.tmp'
    TARGET_DIR="/etc/apache2/mods-available"
    
    SOURCE_FILE="evasive.conf"

    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue
fi

# Mod Security Setup
if apache2ctl -M | grep -q "security2"
then
    echo -e "\n\n${GRE}## Mod Security2 setup BEGIN -----${NCL}"

    mkdir -p /var/log/apache2_mod_security >/dev/null 2>&1
    cp /etc/logrotate.d/apache2 /etc/logrotate.d/apache2-modsec
    sed -i 's#/var/log/apache2/#/var/log/apache2_mod_security/#' "/etc/logrotate.d/apache2-modsec"

    echo -e "\n${GRE}The directory ${YEL}/var/log/apache2_mod_security${GRE} is created. The ${YEL}log rotation${GRE} is set.${NCL}" 

    if [[ ! -f /etc/modsecurity/modsecurity.conf ]]
    then
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        echo -e "\n${GRE}The file ${YEL}/etc/modsecurity/modsecurity.conf${GRE} is created.${NCL}" 
    fi

    if [[ ! -d "/usr/share/modsecurity-crs.3" ]]
    then
        echo -e "\n\n${GRE}## ModSecurity OWASP Core Rule Set 3.x will be installed.${NCL}\n"
        git clone https://github.com/SpiderLabs/owasp-modsecurity-crs /usr/share/modsecurity-crs.3

        /usr/share/modsecurity-crs.3/util/upgrade.py --geoip --crs

        crontab -l | grep -q "/usr/share/modsecurity-crs.3/util/upgrade.py"
        if [[ $? == 1 ]]
        then
            (crontab -l; echo; echo '0 2 * * THU /usr/share/modsecurity-crs.3/util/upgrade.py --geoip --crs --cron >> /var/log/apache2_mod_security/owasp-crs-upgrade.log 2>&1')| crontab -
        fi

        sudo cp /usr/share/modsecurity-crs.3/crs-setup.conf{.example,}
        sudo cp /usr/share/modsecurity-crs.3/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf{.example,}
        sudo cp /usr/share/modsecurity-crs.3/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf{.example,}

        echo -e "\n${YEL}## ModSecurity OWASP Core Rule Set 3.x is installed.${NCL}\n"
    fi

    TEMP_FILE='/tmp/www-security-assistant.tmp'

    SOURCE_FILE="security2.conf"
    TARGET_DIR="/etc/apache2/mods-available"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue
    
    SOURCE_FILE="modsecurity.conf"
    TARGET_DIR="/etc/modsecurity"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="z-customrules.conf"
    TARGET_DIR="/etc/modsecurity"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="crs-setup.conf"
    TARGET_DIR="/usr/share/modsecurity-crs.3"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
    TARGET_DIR="/usr/share/modsecurity-crs.3/rules"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
    TARGET_DIR="/usr/share/modsecurity-crs.3/rules"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="www-security-assistant-issues.php"
    TARGET_DIR="/var/www/html"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="modsecurity-uri-black.list"
    TARGET_DIR="/var/www-security-assistant"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue
fi

# Apache2 configuration files examples

# IPTables example configuration
echo -e "\n\n${GRE}## Establish Apache2 example configuration files.  -----${NCL}"
echo -e "\n${GRE}## Check the files:${NCL}"
echo -e "\n\t/etc/apache2/apache2.conf.example"
echo -e "\n\t/etc/apache2/sites-available/wordpress.conf.example"
echo -e "\n\t/etc/apache2/sites-available/mediawiki.conf.example"
echo

    SOURCE_FILE="apache2.conf.example"
    TARGET_DIR="/etc/apache2"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="wordpress.conf.example"
    TARGET_DIR="/etc/apache2/sites-available"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

    SOURCE_FILE="mediawiki.conf.example"
    TARGET_DIR="/etc/apache2/sites-available"
    SOURCE_URL="${BASE_URL}/appendix${TARGET_DIR}/${SOURCE_FILE}"
    TARGET_FILE="${TARGET_DIR}/${SOURCE_FILE}"
    printf "\n${GRE}## %s${NCL} \n\nSource file:\t${YEL}%s${NCL}\nSource URL:\t%s\nTarget file:\t${YEL}%s${NCL}\n\n${GRE}##${NCL}\n" "${SOURCE_FILE}" "${SOURCE_FILE}" "${SOURCE_URL}" "${TARGET_FILE}"
    wget -q "$SOURCE_URL" -O "$TEMP_FILE"
    installation_dialogue

# IPTables example configuration
echo -ne "\n\n${GRE}## IP Tables - example configuration.  -----\n${GRE}## Read more at: https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-iptables-on-ubuntu-14-04\n${RED}## Follow the next steps on your own risk!${NCL}\n"
echo
echo 'sudo iptables -F'
echo
echo 'sudo iptables -I INPUT 1 -i lo -j ACCEPT'
echo 'sudo iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
echo -e "${GRE}#sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT${NCL}"
echo
echo 'sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT'
echo 'sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT'
echo 'sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT'
echo
echo -e "${GRE}# Create new dedicated chain.\n${YEL}# REQUIRED!${NCL}"
echo 'sudo iptables -N GUARDIAN'
echo 'sudo iptables -I INPUT 3 -j GUARDIAN'
echo
echo -e "${GRE}# Check up:${NCL}"
echo 'sudo iptables -S'
echo 'sudo iptables -L'
echo 'sudo iptables -L GUARDIAN -n'
echo
echo -e "${GRE}# This rule may lock you out of the system!${NCL}"
echo 'sudo iptables -P INPUT DROP'
echo 'sudo iptables -P OUTPUT ACCEPT'
echo
echo -e "\n${GRE}# Test from outside:${NCL}"
echo -e "${GRE}# nmap -p 1-20000 185.80.1.209${NCL}"
echo
echo -e "\n${GRE}# Save and Restore !!! (Tweak the content of the files.)\n${RED}# Be really careful before apply this step !\n# This may lock you out of the system !${NCL}\n"
echo "sudo ln -s ${WORK_DIR}/iptables-save.sh /etc/network/if-post-down.d/iptables-save"
echo "sudo ln -s ${WORK_DIR}/iptables-restore.sh /etc/network/if-pre-up.d/iptables-restore"
echo
#!/bin/sh

# Name:    firewall/firewall.lan-server-behind-nat.sh
# Summary: Add and remove some rules from-to the default iptables settings, provided by SuperHosting.bg to Ubuntu VPS.
# Home:    https://github.com/metalevel-tech/wwwsas
# Author:  Spas Z. Spasov <spas.z.spasov@gmail.com> (C) 2021
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; See the GNU General Public License for more details.
#
# Usage (create .local file, modify and use it inside wwwsas-crontab):
# sudo ./firewall.lan-server-behind-nat.sh.local
# @reboot at crontab
#
# The current setup allows input connections only to these ports:
#   HTTP, HTTPS,
#   SSH (only from trusted IP),
#   CUSTOM_PORT_1 (probably ssh too),
#   CUSTOM_PORT_2 (some other ports, if you do not use it, comment the relevant lines)

# Custom ports and IPs
CUSTOM_PORT_1='10122'
CUSTOM_PORT_2='10222'
CUSTOM_TRUSTED_IP='127.127.127.127'

# Accept loopback interface requests
if iptables -C INPUT -i lo -p all -j ACCEPT >/dev/null 2>&1 || iptables -C INPUT -i lo -j ACCEPT  >/dev/null 2>&1;
then
	echo 'Rule EXIST: INPUT -i lo -j ACCEPT'
else 
	iptables -w -I INPUT 1 -i lo -j ACCEPT
    iptables -w -I FORWARD -i lo -j ACCEPT
fi

# Accept 3 way handshake
if iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT >/dev/null 2>&1; 
then 
	echo 'Rule EXIST: INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT'
else
    iptables -w -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT
    iptables -w -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT
fi

# Define WWWSAS Chains
iptables -w -N WWWSAS_BEFORE
iptables -w -N WWWSAS
iptables -w -I INPUT 3 -j WWWSAS_BEFORE
iptables -w -I INPUT 4 -j WWWSAS

# SSH Backdor, you may want to add or remove rules here
iptables -w -A WWWSAS_BEFORE -m state --state NEW,ESTABLISHED,RELATED --source "$CUSTOM_TRUSTED_IP" -j ACCEPT
iptables -w -A WWWSAS_BEFORE -m state --state NEW,ESTABLISHED,RELATED --source "$CUSTOM_TRUSTED_IP" -p tcp --dport 22 -j ACCEPT
iptables -w -A WWWSAS_BEFORE -m state --state NEW,ESTABLISHED,RELATED --source "$CUSTOM_TRUSTED_IP" -p tcp --dport "$CUSTOM_PORT_1" -j ACCEPT
iptables -w -A WWWSAS_BEFORE -m state --state NEW,ESTABLISHED,RELATED --source "$CUSTOM_TRUSTED_IP" -p tcp --dport "$CUSTOM_PORT_2" -j ACCEPT

# SSH brute-force protection
iptables -w -A WWWSAS_BEFORE -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -w -A WWWSAS_BEFORE -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -w -A WWWSAS_BEFORE -p tcp --dport "$CUSTOM_PORT_1" -m conntrack --ctstate NEW -m recent --set
iptables -w -A WWWSAS_BEFORE -p tcp --dport "$CUSTOM_PORT_1" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
iptables -w -A WWWSAS_BEFORE -p tcp --dport "$CUSTOM_PORT_2" -m conntrack --ctstate NEW -m recent --set
iptables -w -A WWWSAS_BEFORE -p tcp --dport "$CUSTOM_PORT_2" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

# Real protection against Port Scanning via ipset and iptables
iptables -w -A WWWSAS_BEFORE -m state --state INVALID -j DROP
iptables -w -A WWWSAS_BEFORE -m state --state NEW -m set ! --match-set WWWSAS_SCANNED_PORTS src,dst -m hashlimit --hashlimit-above 1/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set WWWSAS_PORT_SCANNERS src --exist
iptables -w -A WWWSAS_BEFORE -m state --state NEW -m set --match-set WWWSAS_PORT_SCANNERS src -j DROP
iptables -w -A WWWSAS_BEFORE -m state --state NEW -j SET --add-set WWWSAS_SCANNED_PORTS src,dst

# Create ipsets relevant to the above rules
ipset create WWWSAS_PORT_SCANNERS hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
ipset create WWWSAS_SCANNED_PORTS hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60

# Add the necessary IN_public_allow rules
iptables -w -A INPUT -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT
iptables -w -A INPUT -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT
iptables -w -A INPUT -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT
iptables -w -A INPUT -p tcp -m tcp --dport "$CUSTOM_PORT_1" -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT
iptables -w -A INPUT -p tcp -m tcp --dport "$CUSTOM_PORT_2" -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT

# ? Drop invalid packets
iptables -w -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -w -A FORWARD -m conntrack --ctstate INVALID -j DROP
iptables -w -A INPUT -j REJECT --reject-with icmp-host-prohibited
iptables -w -A FORWARD -j REJECT --reject-with icmp-host-prohibited
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

# ? Drop TCP packets that are new and are not SYN
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# ? Drop SYN packets with suspicious MSS value
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

# ? Block packets with bogus TCP flags
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# ? Block spoofed packets: be careful with these rules, remove networks that you use
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
#iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
#iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
#iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

# ? Drop ICMP (you usually don't need this protocol) :: If you want to allow ICMP (ping) replace DROP with ACCEPT
iptables -t mangle -A PREROUTING -p icmp -j DROP

# ? Allow ping means ICMP port is open (If you do not want ping replace ACCEPT with REJECT) ---
#iptables -w -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# ? Drop fragments in all chains
iptables -t mangle -A PREROUTING -f -j DROP

# ? Limit connections per source IP, https://making.pusher.com/per-ip-rate-limiting-with-iptables/
iptables -w -A INPUT -p tcp -m connlimit --connlimit-above 111 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with tcp-reset
#iptables -w -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset

# ? Limit new TCP connections per second per source IP
iptables -w -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/sec --limit-burst 40 -j ACCEPT
iptables -w -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

# ? Limit RST packets
iptables -w -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 4/sec --limit-burst 4 -j ACCEPT
iptables -w -A INPUT -p tcp -m tcp --tcp-flags RST RST -j DROP

# Define the default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

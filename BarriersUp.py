#! /usr/bin/env python3

####################################
#        Barriers_UP
#
# Python tool to manage
# Kali hardenings during activities
#
# Credits: futurisiko
####################################

import os
import sys
import subprocess



#################### GLOBAL VARIABLES AND CLASSES ####################

# iptables rules for firewall ON --- block everything except client web browsing
iptables_firewall_on = """
echo " - Flush old rules"
iptables -F
ip6tables -F
echo " - Default drop rules IPv4/IPv6"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
echo " - Enable and protect LO IPv4"
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j DROP
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP
echo " - Drop invalid packets IPv4"
iptables -N INVALIDI
iptables -A INPUT -m state --state INVALID -j INVALIDI
iptables -A OUTPUT -m state --state INVALID -j INVALIDI
iptables -A FORWARD -m state --state INVALID -j INVALIDI
iptables -A INVALIDI -j DROP 
echo " - Drop fragmented packets IPv4"
iptables -N FRAMMENTI
iptables -A INPUT -f -j FRAMMENTI
iptables -A FRAMMENTI -j DROP
echo " - Drop xmas packets IPv4"
iptables -N XMAS
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j XMAS
iptables -A XMAS -j DROP
echo " - Drop null packets IPv4"
iptables -N NULLI
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j NULLI
iptables -A NULLI -j DROP
echo " - Drop tcp without handshake IPv4"
iptables -N NOSYN
iptables -A OUTPUT -p tcp ! --syn -m state --state NEW -j NOSYN
iptables -A NOSYN -j DROP
echo " - Enable http/https IPv4"
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
echo " - Enable dns IPv4"
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
echo " - Drop remaining IPv4"
iptables -A OUTPUT -j DROP
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
echo " - Enable and protect LO IPv6"
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT ! -i lo -d ::1/128 -j DROP
ip6tables -A INPUT ! -i lo -s ::1/128 -j DROP
echo " - Drop remaining IPv6"
ip6tables -A INPUT -j DROP
ip6tables -A OUTPUT -j DROP
ip6tables -A FORWARD -j DROP
"""

# iptables rules for firewall OFF --- allow all network traffic and delete chains defined in the "firewall ON" rules's list 
iptables_firewall_off = """
echo " - Flush old rules"
iptables -F
ip6tables -F
echo " - Delete user defined rules IPv4"
iptables -X INVALIDI
iptables -X FRAMMENTI
iptables -X XMAS
iptables -X NULLI
iptables -X NOSYN
echo " - Allow all connections IPv4"
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
echo " - Allow all connections IPv6"
ip6tables -P INPUT ACCEPT
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD ACCEPT
"""

# check firewall rules in place
iptables_rules_inplace = """
iptables -S | grep -v '\-N' | awk '{ gsub(/-P/, " Default:") } 1' | awk '{ gsub(/-A/, "") } 1'
"""

# apache process variable
apache_process = "apache2"

# bash commands to start apache server
bash_apache_start = """
systemctl start apache2
systemctl status apache2
"""

# bash commands to stop apache server
bash_apache_stop = """
systemctl stop apache2
systemctl status apache2
"""

# bash oneliner to print and grab info about Fail2ban jails
bash_status_quick_command = """
for i in $(fail2ban-client status | grep 'Jail list' | awk -F: '{ print $2 }' | awk '{gsub(" ", "\\n")}1' | awk '{ gsub(/[\\t,]/, "") } 1'); do for u in "Status" "banned" "Banned"; do fail2ban-client status $i | grep --color=never $u; done; done
"""

# fail2ban process variable
fail2ban_process = "fail2ban"

# bash commands to restart fail2ban after a new rule is added
fail2ban_reload = """
echo " - JAIL added !"
echo " "
systemctl restart fail2ban
systemctl status fail2ban
"""

# bash oneliner to print and grab full info about Fail2ban jails
fail2ban_bash_status_full_command = """
for i in $(fail2ban-client status | grep 'Jail list' | awk -F: '{ print $2 }' | awk '{gsub(" ", "\\n")}1' | awk '{ gsub(/[\\t,]/, "") } 1'); do fail2ban-client status $i; done
"""

# fail2ban jail.local path
jail_local_path = '/etc/fail2ban/jail.local'

# bash commands to start fail2ban and setup its iptables chains
fail2ban_start_commands = """
touch /etc/fail2ban/jail.local
echo " - Fail2ban Apache drop iptables chain creation"
iptables -N fail2banApache
iptables -I INPUT -j fail2banApache
iptables -A fail2banApache -j RETURN
echo " - Fail2ban SSH drop iptables chain creation"
iptables -N fail2banSSH
iptables -I INPUT -j fail2banSSH
iptables -A fail2banSSH -j RETURN
echo " - Fail2ban Portsentry drop iptables chain creation"
iptables -N fail2banPortsentry
iptables -I INPUT -j fail2banPortsentry
iptables -A fail2banPortsentry -j RETURN
echo " "
systemctl start fail2ban
systemctl status fail2ban
"""

# bash commands to stop fail2ban and clear its iptables chains 
fail2ban_stop_commands = """
systemctl stop fail2ban
systemctl status fail2ban
echo " "
echo " - Deleting Fail2ban Apache iptables chain"
iptables -D INPUT $(iptables -L INPUT --line-numbers | grep fail2banApache | cut -d " " -f 1)
iptables -F fail2banApache
iptables -X fail2banApache
echo " - Deleting Fail2ban SSH iptables chain"
iptables -D INPUT $(iptables -L INPUT --line-numbers | grep fail2banSSH | cut -d " " -f 1)
iptables -F fail2banSSH
iptables -X fail2banSSH
echo " - Deleting Fail2ban Portsentry iptables chain"
iptables -D INPUT $(iptables -L INPUT --line-numbers | grep fail2banPortsentry | cut -d " " -f 1)
iptables -F fail2banPortsentry
iptables -X fail2banPortsentry
"""

# Fail2ban jail setup to blocks failed login attempts
fail2ban_apache_auth = """
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 3
bantime = 600
ignoreip = 127.0.0.1
chain = fail2banApache
backend = polling
"""

# Fail2ban jail to blocks remote clients who search and executes the scripts 
fail2ban_apache_noscript = """
[apache-noscript] 
enabled = true 
port = http,https 
filter = apache-noscript 
logpath = /var/log/apache2/*error.log 
maxretry = 3 
bantime = 600 
ignoreip = 127.0.0.1
chain = fail2banApache
backend = polling
"""

# Fail2ban jail to block clients who are attempting to request suspicious URLs 
fail2ban_apache_overflows = """
[apache-overflows] 
enabled = true 
port = http,https 
filter = apache-overflows 
logpath = /var/log/apache2/*error.log 
maxretry = 3 
bantime = 600 
ignoreip = 127.0.0.1
chain = fail2banApache
backend = polling
"""

# Fail2ban jail to block malicious bot requests 
fail2ban_apache_badbots = """
[apache-badbots] 
enabled = true 
port = http,https 
filter = apache-badbots 
logpath = /var/log/apache2/*error.log 
maxretry = 3
bantime = 600 
ignoreip = 127.0.0.1
chain = fail2banApache
backend = polling
"""

# ssh process variable
ssh_process = "sshd"

# Fail2ban jail to block attempts to brute force SSH logins
fail2ban_ssh_login = """
[ssh] 
enabled = true 
port = ssh 
filter = sshd 
logpath = /var/log/auth.log 
maxretry = 3
bantime = 600
ignoreip = 127.0.0.1
chain = fail2banSSH
"""

# bash commands to start ssh server
ssh_start_commands = """
systemctl start ssh
systemctl status ssh
"""

# bash commands to stop ssh server
ssh_stop_commands = """
systemctl stop ssh
systemctl status ssh
"""

# bash commands to refresh SSH keys
regen_ssh_default_keys = """
echo " - Deleting default SSH keys"
rm -rf /etc/ssh/ssh_host_*
echo " - Regenerating SSH keys"
echo " "
dpkg-reconfigure openssh-server
"""

# portsentry process variable
portsentry_process = "portsentry"

# Fail2ban jail setup for portsentry
portsentry_fail2ban_rule = """
[portsentry]
enabled = true
logpath = /var/lib/portsentry/portsentry.history
maxretry = 1
bantime = 3600
chain = fail2banPortsentry
backend = polling
"""

# bash commands to start Portsentry
portsentry_start_commands = """
echo " - Portsentry setup"
rm -rf /var/lib/portsentry/portsentry.history
touch /var/lib/portsentry/portsentry.history
echo " - Setting Portsentry in Logging ONLY mode"
ln -sf /dev/null /var/lib/portsentry/portsentry.blocked.stcp
ln -sf /dev/null /var/lib/portsentry/portsentry.blocked.sudp
ln -sf /dev/null /var/lib/portsentry/portsentry.blocked.tcp
ln -sf /dev/null /var/lib/portsentry/portsentry.blocked.udp
echo " - Setting Portsentry in Stealth Mode"
sed -i 's/TCP_MODE="tcp"/TCP_MODE="stcp"/' /etc/default/portsentry
sed -i 's/UDP_MODE="udp"/UDP_MODE="sudp"/' /etc/default/portsentry
echo " "
systemctl start portsentry.service 
systemctl restart portsentry.service 
systemctl status portsentry.service
"""

# bash commands to stop Portsentry
portsentry_stop_commands = """
systemctl stop portsentry.service
systemctl status portsentry.service
"""

# bash commands to print, organize and sort full offender list
portsentry_check_full_offender = """
echo " - Full list sorted by attempts:"
cat /var/lib/portsentry/portsentry.history | cut -d " " -f 2,6,8 | sort | uniq -c | sort -nr |  sed 's/     //'
"""

# view full list
portsentry_check_top5_offender = """
echo " - Top 5 list sorted by attempts:"
cat /var/lib/portsentry/portsentry.history | cut -d " " -f 2,6 | cut -d "/" -f 1 | sort | uniq -c | sort -nr | head -n 5 |  sed 's/     //'
"""

# text colors
class bcolors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    ENDC = '\033[0m'
    backBlack = '\033[40m'
    backRed = '\033[41m'
    backGreen = '\033[42m'
    backYellow = '\033[43m'
    backBlue = '\033[44m'
    backMagenta = '\033[45m'
    backCyan = '\033[46m'
    backWhite = '\033[47m'

    
    
#################### DEFs ####################

# graphic banner def
def graphic_banner():
    os.system("clear")
    print(bcolors.GREEN + "\n" + r"""
    dBBBBb dBBBBBb   dBBBBBb  dBBBBBb    dBP dBBBP dBBBBBb .dBBBBP      dBP dBP dBBBBBb
       dBP      BB       dBP      dBP                  dBP BP                       dB'
   dBBBK'   dBP BB   dBBBBK   dBBBBK   dBP dBBP    dBBBBK  `BBBBb     dBP dBP   dBBBP' 
  dB' db   dBP  BB  dBP  BB  dBP  BB  dBP dBP     dBP  BB     dBP    dBP_dBP   dBP     
 dBBBBP'  dBBBBBBB dBP  dB' dBP  dB' dBP dBBBBP  dBP  dB'dBBBBP'    dBBBBBP   dBP      
 """ + bcolors.ENDC)	

# exit def
def exit_routine():
    print("\n Exiting.")
    print("\n Cya dude & " + bcolors.GREEN + "Hack " + bcolors.YELLOW + "the " + bcolors.RED + "planet" + bcolors.ENDC + "\n" )
    sys.exit()

# def OS check
def check_os():
    if os.name == "nt":
        operating_system = "windows"
    if os.name == "posix":
        operating_system = "posix"
    return operating_system

# def to run bash commands
def run_bash_commands(commands):
    graphic_banner()
    print("\n ------------ Executing -----------")
    for command in commands:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stdout:
            print(f" {stdout.decode().strip()}")
        if stderr:
            print(f" " + bcolors.YELLOW + f"{stderr.decode().strip()}" + bcolors.ENDC)
    print(" -------------- Done --------------")

# def to check process presence
def is_process_running(process_name):
    try:
        subprocess.run(["pgrep", "-f", process_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False
        
# def firewall ON
def firewall_on():
    if not is_process_running(fail2ban_process):
        run_bash_commands(iptables_firewall_on.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban running! " + bcolors.RED + "***" + bcolors.ENDC)
        print(" Please stop Fail2ban before changing iptables chains.")
        print(" Restart it after changes are made, if needed.")

# def firewall OFF
def firewall_off():
    if not is_process_running(fail2ban_process):
        run_bash_commands(iptables_firewall_off.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban running! " + bcolors.RED + "***" + bcolors.ENDC)
        print(" Please stop Fail2ban before changing iptables chains.")
        print(" Restart it after changes are made, if needed.")

# add firewall rule on the fly
def add_firewall_rule():
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print("\n ------------ Executing -----------")    
        print(" Exposing a service")
        user_port_input = input(" Port you want to open: ")
        if user_port_input.isdigit():
            port_number = int(user_port_input)
            subprocess.run(f'iptables -I INPUT -p tcp --dport {port_number} -j ACCEPT', shell=True, check=True)
            subprocess.run(f'iptables -I INPUT -p udp --dport {port_number} -j ACCEPT', shell=True, check=True)
            subprocess.run(f'iptables -I OUTPUT -p tcp --sport {port_number} -j ACCEPT', shell=True, check=True)
            subprocess.run(f'iptables -I OUTPUT -p udp --sport {port_number} -j ACCEPT', shell=True, check=True)
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid input. Please write a legit number " + bcolors.RED + "***" + bcolors.ENDC)
        print(" Port OPENED")
        print(" -------------- Done --------------")
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban running! " + bcolors.RED + "***" + bcolors.ENDC)
        print(" Please stop Fail2ban before changing iptables chains.")
        print(" Restart it after changes are made, if needed.")

# def to print iptables rules in place
def print_iptables_rules() :
    graphic_banner()
    run_bash_commands(iptables_rules_inplace.strip().splitlines())
        
# def start apache
def apache_start():
    if not is_process_running(apache_process):
        run_bash_commands(bash_apache_start.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Apache already working " + bcolors.RED + "***" + bcolors.ENDC)
    
# def stop apache2
def apache_stop():
    if not is_process_running(apache_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Apache already stopped " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(bash_apache_stop.strip().splitlines())       

# def to start fail2ban service
def start_fail2ban():
    if not is_process_running(fail2ban_process):
        run_bash_commands(fail2ban_start_commands.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban already working " + bcolors.RED + "***" + bcolors.ENDC)
    
# def to stop fail2ban service
def stop_fail2ban():
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban already stopped " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(fail2ban_stop_commands.strip().splitlines())

# def to quick check logs
def banned_status_quick():
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban not running! " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(bash_status_quick_command.strip().splitlines())         
        
# def to check fail2ban full logs
def fail2ban_banned_status_full():
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban not running! " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(fail2ban_bash_status_full_command.strip().splitlines()) 

# def to check jail.local actual setup
def check_fail2ban_local_config():
    if not os.path.exists(jail_local_path):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " jail.local not present. Restart Fail2ban or add some jails " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        graphic_banner()
        with open(jail_local_path, 'r') as file:
            jail_local_content = file.read()
            print(bcolors.GREEN + "\n +++" + bcolors.ENDC + " jail.local actual content " + bcolors.GREEN + "+++" + bcolors.ENDC)
            print(jail_local_content)

# def to add jail rules and restart fail2ban after
def add_fail2ban_jail_setup(jail_rule):
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Before playing with jails start Fail2ban " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        graphic_banner()
        with open(jail_local_path, 'a') as file:
            file.write('\n')  # Ensure there's a newline before appending new content
            file.write(jail_rule)
        run_bash_commands(fail2ban_reload.strip().splitlines())

# def to purge jail.local config file
def purge_jail_local():
    if not os.path.exists(jail_local_path):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " jail.local already deleted " + bcolors.RED + "***" + bcolors.ENDC)
        print(" To regenerate it restart Fail2ban")
    else:
        graphic_banner()
        os.remove(jail_local_path)
        print(bcolors.GREEN + "\n +++" + bcolors.ENDC + " jail.local purged! " + bcolors.GREEN + "+++" + bcolors.ENDC)
        print(" To regenerate it restart Fail2ban")
        
# def to unban target IP
def fail2ban_unban_ip():
    if not is_process_running(fail2ban_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Fail2ban stopped! " + bcolors.RED + "***" + bcolors.ENDC)
        print(" Please start Fail2ban.")
    else:
        graphic_banner()
        print("\n ------------ Executing -----------")    
        print(" Unban target IP")
        target_jail_name = input(" Name of the target jail: ")
        if all(c.isalpha() or c == '-' for c in target_jail_name):
            target_ip_unban = input(" IP to unban: ")
            if all(c.isdigit() or c == '.' for c in target_ip_unban):
                subprocess.run(f'fail2ban-client set {target_jail_name} unbanip {target_ip_unban}', shell=True, check=True)
                print(" Unbanned target IP.")
                print(" -------------- Done --------------")
            else:
                graphic_banner()
                print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid IP. Please write a legit number " + bcolors.RED + "***" + bcolors.ENDC)    
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid jail name " + bcolors.RED + "***" + bcolors.ENDC)
        
# def to start ssh server
def start_ssh():
    if not is_process_running(ssh_process):
        run_bash_commands(ssh_start_commands.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " SSH server already running " + bcolors.RED + "***" + bcolors.ENDC)

# def to stop ssh server
def stop_ssh():
    if not is_process_running(ssh_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " SSH server already stopped " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(ssh_stop_commands.strip().splitlines())

# def to regen default ssh keys
def regen_keys():
    if not is_process_running(ssh_process):
        run_bash_commands(regen_ssh_default_keys.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Stop SSH server before keys regen " + bcolors.RED + "***" + bcolors.ENDC)

# def to start portsentry service
def start_portsentry():
    if not is_process_running(portsentry_process):
        run_bash_commands(portsentry_start_commands.strip().splitlines())
    else:
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Portsentry already working " + bcolors.RED + "***" + bcolors.ENDC)
    
# def to stop portsentry service
def stop_portsentry():
    if not is_process_running(portsentry_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Portsentry already stopped " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(portsentry_stop_commands.strip().splitlines())

# def to check portsentry full logs
def portsentry_log_status_full():
    if not is_process_running(portsentry_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Portsentry not running! " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(portsentry_check_full_offender.strip().splitlines()) 

# def to check portsentry top 5 offenders
def portsentry_top5_offenders():
    if not is_process_running(portsentry_process):
        graphic_banner()
        print(bcolors.RED + "\n ***" + bcolors.ENDC + " Portsentry not running! " + bcolors.RED + "***" + bcolors.ENDC)
    else:
        run_bash_commands(portsentry_check_top5_offender.strip().splitlines())

# def to print services status
def print_service_status():
    #detect if running or not
    if not is_process_running(fail2ban_process):
        fail2ban_status = f"{bcolors.RED}OFF{bcolors.ENDC}"
    else:
        fail2ban_status = f"{bcolors.GREEN}ON{bcolors.ENDC}"
    if not is_process_running(apache_process):
        apache_status = f"{bcolors.RED}OFF{bcolors.ENDC}"
    else:
        apache_status = f"{bcolors.GREEN}ON{bcolors.ENDC}"
    if not is_process_running(ssh_process):
        ssh_status = f"{bcolors.RED}OFF{bcolors.ENDC}"
    else:
        ssh_status = f"{bcolors.GREEN}ON{bcolors.ENDC}"
    if not is_process_running(portsentry_process):
        portsentry_status = f"{bcolors.RED}OFF{bcolors.ENDC}"
    else:
        portsentry_status = f"{bcolors.GREEN}ON{bcolors.ENDC}"
    print(bcolors.CYAN + "\n Services status:" + bcolors.ENDC)
    print(f" Apache service {apache_status} - SSH service {ssh_status} - Fail2ban service {fail2ban_status} - Portsentry service {portsentry_status}")
    
    
    
#################### MENUs ####################

# apache menu
def apache_menu():

    # option list
    options = {
        '1': 'Apache server ' + bcolors.GREEN + 'ON' + bcolors.ENDC + '.',
        '2': 'Apache server ' + bcolors.RED + 'OFF' + bcolors.ENDC + '.',
        '3': 'Add web jails (jump to Fail2ban).',
        '98': 'Refresh terminal.',
        '99': 'Back to main menu.'
    }
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:
        
        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n Apache menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            apache_start()
        elif choice == '2':
            apache_stop()
        elif choice == '3':
            fail2ban_menu()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            main_menu()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")

# ssh menu
def ssh_menu():

    # option list
    options = {
        '1': 'SSH server ' + bcolors.GREEN + 'ON' + bcolors.ENDC + '.',
        '2': 'SSH server ' + bcolors.RED + 'OFF' + bcolors.ENDC + '.',
        '3': 'Regenerate SSH server keys.',
        '4': 'Start bruteforce filter (jump to Fail2ban).',
        '98': 'Refresh terminal.',
        '99': 'Back to main menu.'
    }
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:
        
        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n SSH menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            start_ssh()
        elif choice == '2':
            stop_ssh()
        elif choice == '3':
            regen_keys()
        elif choice == '4':
            fail2ban_menu()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            main_menu()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")

# fail2ban menu
def fail2ban_menu():

    # option list
    options = {
        '1': 'Fail2ban ' + bcolors.GREEN + 'ON' + bcolors.ENDC + '.',
        '2': 'Fail2ban ' + bcolors.RED + 'OFF' + bcolors.ENDC + '.',
        '3': 'Fail2ban: ' + bcolors.BOLD + bcolors.YELLOW + 'full log view' + bcolors.ENDC + '.',
        '4': 'Check existing jails setup.',
        '5': 'Purge all jails config.',
        '6': 'Add apache-auth jail (blocks failed login attempts).',
        '7': 'Add apache-noscript jail (block scripts search and execution).',
        '8': 'Add apache-overflows jail (block request to suspicious URLs).',
        '9': 'Add apache-badbots jail (block malicious bot requests).',
        '10': 'Add ssh-auth jail (block attempts to brute force SSH logins).',
        '11': 'Add portsentry jail (block offenders logged via portsentry)',
        '12': 'Unban target IP (need connected jail name and target IP)',
        '98': 'Refresh terminal.',
        '99': 'Back to main menu.'
    }
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:
        
        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n Fail2ban menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            start_fail2ban() 
        elif choice == '2':
            stop_fail2ban() 
        elif choice == '3':
            fail2ban_banned_status_full()
        elif choice == '4':
            check_fail2ban_local_config()
        elif choice == '5':
            purge_jail_local()
        elif choice == '6':
            add_fail2ban_jail_setup(fail2ban_apache_auth)
        elif choice == '7':
            add_fail2ban_jail_setup(fail2ban_apache_noscript)
        elif choice == '8':
            add_fail2ban_jail_setup(fail2ban_apache_overflows)
        elif choice == '9':
            add_fail2ban_jail_setup(fail2ban_apache_badbots)
        elif choice == '10':
            add_fail2ban_jail_setup(fail2ban_ssh_login)
        elif choice == '11':
            add_fail2ban_jail_setup(portsentry_fail2ban_rule)
        elif choice == '12':
            fail2ban_unban_ip()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            main_menu()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")        

# firewall menu
def firewall_menu():
    
    # option list
    options = {
        '1': 'Firewall ' + bcolors.GREEN + 'ON' + bcolors.ENDC +' : only http/https/dns traffic allowed.',
        '2': 'Firewall ' + bcolors.RED + 'OFF' + bcolors.ENDC + ' : clear all iptables rules.',
        '3': 'Check iptables rules in place.',
        '4': 'Expose manually a service.',
        '98': 'Refresh terminal.',
        '99': 'Exit.'
    }   
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:

        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n Firewall Menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            firewall_on()
        elif choice == '2':
            firewall_off()
        elif choice == '3':
            print_iptables_rules()
        elif choice == '4':
            add_firewall_rule()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            main_menu()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")

# portsentry menu
def portsentry_menu():
    
    # option list
    options = {
        '1': 'Portsentry ' + bcolors.GREEN + 'ON' + bcolors.ENDC +'.',
        '2': 'Portsentry ' + bcolors.RED + 'OFF' + bcolors.ENDC + '.',
        '3': 'View full offenders list from Portsentry logs.',
        '4': 'Add a Fail2ban jail (block offenders).',
        '98': 'Refresh terminal.',
        '99': 'Exit.'
    }   
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:

        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n Portsentry Menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            start_portsentry()
        elif choice == '2':
            stop_portsentry()
        elif choice == '3':
            portsentry_log_status_full()
        elif choice == '4':
            fail2ban_menu()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            main_menu()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")            

# main menu 
def main_menu():
    
    # option list
    options = {
        '1': 'Fail2ban ' + bcolors.GREEN + 'quick log view' + bcolors.ENDC + '.',
        '2': 'Portsentry ' + bcolors.GREEN + 'top 5 logs' + bcolors.ENDC + '.',
        '3': 'Firewall menu.',
        '4': 'Apache menu.',
        '5': 'SSH menu.',
        '6': 'Fail2ban menu.',
        '7': 'Portsentry menu.',
        '98': 'Refresh terminal.',
        '99': 'Exit.'
    }   
    
    # initial banner
    graphic_banner()
    
    # while loop to manage the menu
    while True:

        # print services status
        print_service_status()
        # print menu
        print(bcolors.CYAN + "\n Main menu:" + bcolors.ENDC)
        for number, description in options.items():
            print(f" {number} - {description}")
        
        # choise available
        choice = input("\n Enter the number of your choice: ")
        if choice == '1':
            banned_status_quick()
        elif choice == '2':
            portsentry_top5_offenders()
        elif choice == '3':
            firewall_menu()
        elif choice == '4':
            apache_menu()
        elif choice == '5':
            ssh_menu()
        elif choice == '6':
            fail2ban_menu()
        elif choice == '7':
            portsentry_menu()
        elif choice == '98':
            graphic_banner()
        elif choice == '99':
            exit_routine()
        else:
            graphic_banner()
            print(bcolors.RED + "\n ***" + bcolors.ENDC + " Invalid choice " + bcolors.RED + "***" + bcolors.ENDC)
            print(" Please enter a number from the menu.")




#################### MAIN ####################
        
# check it's linux and root permission
if check_os() == "posix":
    if os.geteuid() != 0:
        graphic_banner()
        print("\n Need to run as " + bcolors.backRed + "Root" + bcolors.ENDC + "!")
        exit_routine()
else:
    graphic_banner()
    print("\n Only for " + colors.backRed + "Linux" + bcolors.ENDC + "!")
    exit_routine()

# start main menu
if __name__ == "__main__":
    main_menu()
    

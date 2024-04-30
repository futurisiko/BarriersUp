# BarriersUp
Python tool to ***manage Kali system hardening*** during assessments. <br>
```
    dBBBBb dBBBBBb   dBBBBBb  dBBBBBb    dBP dBBBP dBBBBBb .dBBBBP      dBP dBP dBBBBBb
       dBP      BB       dBP      dBP                  dBP BP                       dB'
   dBBBK'   dBP BB   dBBBBK   dBBBBK   dBP dBBP    dBBBBK  `BBBBb     dBP dBP   dBBBP' 
  dB' db   dBP  BB  dBP  BB  dBP  BB  dBP dBP     dBP  BB     dBP    dBP_dBP   dBP     
 dBBBBP'  dBBBBBBB dBP  dB' dBP  dB' dBP dBBBBP  dBP  dB'dBBBBP'    dBBBBBP   dBP      
 

 Services status:
 Apache service OFF - SSH service OFF - Fail2ban service OFF - Portsentry service OFF

 Main menu:
 1 - Fail2ban quick log view.
 2 - Portsentry top 5 logs.
 3 - Firewall menu.
 4 - Apache menu.
 5 - SSH menu.
 6 - Fail2ban menu.
 7 - Portsentry menu.
 98 - Refresh terminal.
 99 - Exit.

 Enter the number of your choice: 
```
I got the idea from this Tristram's repository: https://github.com/gh0x0st/Secure_Kali <br>
The tool is based on methodologies outlined in that repository. <br>
The idea was to use them to build a ***one-stop shop tool*** to use during assessments. <br>
## SETUP
You need to install ```fail2ban``` and ```portsentry```, other dependecies should be ***already installed*** in ***Kali***.
```
sudo apt update && sudo apt install fail2ban portsentry -y
```
## QUICK OVERVIEW
Basically the tool offers the possibility to easily manage some common services and some hardening connected to them. <br>
It must be run with ***root privileges***.
```
sudo chmod +x ./BarriersUp.py
sudo ./BarriersUp.py
```
***MAIN MENU***:
```
 Services status:
 Apache service OFF - SSH service OFF - Fail2ban service OFF - Portsentry service OFF

 Main menu:
 1 - Fail2ban quick log view.
 2 - Portsentry top 5 logs.
 3 - Firewall menu.
 4 - Apache menu.
 5 - SSH menu.
 6 - Fail2ban menu.
 7 - Portsentry menu.
 98 - Refresh terminal.
 99 - Exit.

 Enter the number of your choice: 
```
***Services Status*** : banner present in all menus to monitor if services are activated. <br>
***1 - Fail2ban quick log view*** : output Fail2ban jails' log to monitor if some actions were taken against some IPs. <br>
***2 - Portsentry top 5 logs*** : output top 5 IPs caught scanning you by Portsentry. <br><br>
***3 - Firewall menu*** : sub-menu dedicated to firewall rules. <br>
```
 Firewall Menu:
 1 - Firewall ON : only http/https/dns traffic allowed.
 2 - Firewall OFF : clear all iptables rules.
 3 - Check iptables rules in place.
 4 - Expose manually a service.
```
"***Firewall ON***" sets up an example of iptables chains that allow only client internet traffic. Others options are pretty clear. <br>
"***Expose manually a service***" could be useful if, for example, you want to expose your Apache instance keeping the Firewall ON.<br>
If you want to customize those default rules search these variables in the tool's code: ```iptables_firewall_on``` and ```iptables_firewall_off```. <br><br>
***4 - Apache menu*** : sub-menu dedicated to Apache service. <br>
```
 Apache menu:
 1 - Apache server ON.
 2 - Apache server OFF.
 3 - Add web jails (jump to Fail2ban).
```
"***Apache server ON/OFF***" activate/deactivate Apache service. <br>
"***Add web jails***" directly jump into the Fail2ban sub-menu. <br>
In that menu you will be able to setup some Apache specific jails to ban stange behaviours. <br><br>
***5 - SSH menu*** : sub-menu dedicated to SSH service. <br>
```
 SSH menu:
 1 - SSH server ON.
 2 - SSH server OFF.
 3 - Regenerate SSH server keys.
 4 - Start bruteforce filter (jump to Fail2ban).
```
"***SSH server ON/OFF***" activate/deactivate SSH service. <br>
"***Regenerate SSH server keys***" quickly delete your SSH actual keys and regenerate them via ```dpkg-reconfigure```. <br>
"***Start bruteforce filter***" jumps to Fail2ban sub-menu where you can setup a jail to ban bruteforce attack against your SSH service. <br><br>
***6 - Fail2ban menu*** : sub-menu dedicated to Fail2ban service. <br>
```
 Fail2ban menu:
 1 - Fail2ban ON.
 2 - Fail2ban OFF.
 3 - Fail2ban: full log view.
 4 - Check existing jails setup.
 5 - Purge all jails config.
 6 - Add apache-auth jail (blocks failed login attempts).
 7 - Add apache-noscript jail (block scripts search and execution).
 8 - Add apache-overflows jail (block request to suspicious URLs).
 9 - Add apache-badbots jail (block malicious bot requests).
 10 - Add ssh-auth jail (block attempts to brute force SSH logins).
 11 - Add portsentry jail (block offenders logged via portsentry)
 12 - Unban target IP (need connected jail name and target IP)
```
"***Fail2ban ON/OFF***" activate/deactivate Fail2ban service. <br>
"***Fail2ban: full log view***" output full Fail2ban log as written. <br>
"***Check existing jails setup***" output the actual ***/etc/fail2ban/jail.local*** content. <br>
"***Purge all jails config***" delete ***/etc/fail2ban/jail.local*** file and reload the service. <br>
***From "6" to "11"*** there are commands to add specific jails examples. <br><br>
These commands will add a specific jail setup into the ***/etc/fail2ban/jail.local*** file and will reload the service. <br>
So, to change Fail2ban jails setup the intended workflow is: <br>
&emsp;- Purge the actual config <br>
&emsp;- Add jails you want <br><br>
All jails setups are stored as text variables at the beginning of the code. <br>
Feel free to customize them according to your needs. <br><br>
"***Unban target IP***" is used to unban someone actually locked by a specific jail. <br><br>
***7 - Portsentry menu*** : sub-menu dedicated to Portsentry service. <br>
```
 Portsentry Menu:
 1 - Portsentry ON.
 2 - Portsentry OFF.
 3 - View full offenders list from Portsentry logs.
 4 - Add a Fail2ban jail (block offenders).
```
"***Portsentry ON/OFF***" activate/deactivate Portsentry service. <br>
"***View full offenders list***" output the complete Portsentry log. <br>
"***Add a Fail2ban jail***" jumps directly to Fail2ban sub-menu where you can add a jail to ban IPs logged by Portsentry. <br><br>
By default it runs Portsentry in ***stealth mode*** with the ***default ports list***. <br>
It works pretty well for catching standard scan attempts (also -sS ones). <br>
If you want to customize ports list you have to look at ```TCP_PORTS``` and ```UDP_PORTS``` in the ```/etc/portsentry/portsentry.conf``` file. <br>
Instead, to change Portsentry behaviour from ***stealth*** to (for e.g.) ***standard*** mode you have to look at the ```portsentry_start_commands``` variable inside the tool's code. <br>
Once you find it change ```sed``` instruction from this:
```
sed -i 's/TCP_MODE="tcp"/TCP_MODE="stcp"/' /etc/default/portsentry
sed -i 's/UDP_MODE="udp"/UDP_MODE="sudp"/' /etc/default/portsentry
```
to this:
```
sed -i 's/TCP_MODE="stcp"/TCP_MODE="tcp"/' /etc/default/portsentry
sed -i 's/UDP_MODE="sudp"/UDP_MODE="udp"/' /etc/default/portsentry
```
## INSTALLATION
If you want to quickly deploy the tool inside your Kali:
```
sudo apt update && sudo apt install fail2ban portsentry -y
git clone https://github.com/futurisiko/BarriersUp.git
cd BarriersUp
sudo chmod +x BarriersUp.py
sudo cp BarriersUp.py /usr/local/bin/BarriersUp
sudo BarriersUp
```
## SNORT VARIANT
This is an update version that implements also some useful snort's commands/integrations.
Need to have snort installed (v2) and ```snort.conf``` + rules folder in ```/etc/snort/```.




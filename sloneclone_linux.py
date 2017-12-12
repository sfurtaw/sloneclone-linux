#!/usr/bin/python3
# sloneclone-linux.py
# CyberPatriot Python Linux script for team "Slone clones in the danger zone we swear we know what we're doing"
#-------------- IMPORTS
import os
import sys
import getpass
import platform
import subprocess

#-------------- COLORS
# Nice colors definitely not stolen from Blender source
class color:
	header = '\033[95m'
	okblue = '\033[94m'
	okgreen = '\033[92m'
	warning = '\033[93m'
	fail = '\033[91m'
	endc = '\033[0m'
	bold = '\033[1m'
	underline = '\033[4m'

#-------------- VARS
# Set temp variables for later
mediafiles=apps=distribution=deluser=adduser=group=demote=exceptionport=sudoers=confirm="temp"

#-------------- FUNCTIONS
def call(command):
# Call a command as a subprocess
	return subprocess.call(str(command),shell=True)
	
def checkoutput(command):
# Call a subprocess, silence output/check output as variable
	return subprocess.check_output(str(command),shell=True,universal_newlines=True)
	
def fail(text):
# Set failure color and print text
	print(color.fail + str(text) + color.endc)
	
def blue(text):
# Set blue color and print text
	print(color.okblue + str(text) + color.endc)
	
def green(text):
# Set OK (green) color and print text
	print(color.okgreen + str(text) + color.endc)

def warning(text):
# Set warning color and print text
	print(color.warning + str(text) + color.endc)

def boldinput(text):
# Ask for input, set bold color
	return input(color.bold + str(text) + color.endc)
	
def bold(text):
# Print text in bold
	print(color.bold + str(text) + color.endc)

def underline(text):
# Print text underlined
	print(color.underline + str(text) + color.endc)
	
def uninstall(list):
# Take a list and attempt to uninstall all packages in list
	try:
		bold("Removing " + "/".join(list) + " using " + aptcommand + " ...")
		for uninstallapp in list:
			call(aptcommand + " purge -y " + str(uninstallapp))
	except:
		fail("Removing " + "/".join(list) + " failed.")
		
def install(list):
# Take a list and attempt to install all packages in list
	try:
		bold("Installing " + "/".join(list) + " using " + str(aptcommand) + "...")
		for installapp in list:
			call(str(aptcommand) + " install -y " + str(installapp))
	except:
		fail("Installing " + "/".join(list) + " failed.")

def restartservice(service):
# Restart service with distribution-specific command
	if os.path.exists("/bin/systemctl"):
		bold("Restarting " + str(service) + " via systemctl...")
		call("systemctl restart " + str(service))
	elif os.path.exists("/usr/sbin/service"):
		bold("Restarting " + str(service) + " via upstart...")
		call("service " + str(service) + " restart")
		
def disableservice(service):
# Restart service with distribution-specific command
	if os.path.exists("/bin/systemctl"):
		bold("Disabling " + str(service) + " via systemctl...")
		call("systemctl disable " + str(service))
	elif os.path.exists("/usr/sbin/service"):
		bold("Disabling " + str(service) + " via upstart...")
		checkoutput("echo manual > /etc/init/" + str(service) + ".override")
		
#-------------- CHECKS
# Check for 'debug' command-line argument for testing
if len(sys.argv) > 1 and "skipplatform" in sys.argv:
	warning("Debug mode, skipping platform check...")
# Skip OS and version checks if debug mode is enabled
# Make sure the OS platform is Linux, error out if otherwise
elif platform.system() != 'Linux':
	fail(platform.system() + " platform is not supported. Exiting...")
	sys.exit()
# Make sure Python version 3 is in use, error out if otherwise
elif list(sys.version_info)[0] < 3:
	fail("Python version " + platform.python_version() +  " is unsupported. Python version must be 3+. Exiting...")
	sys.exit()
# Check the user is root
elif getpass.getuser() != 'root':
	fail("Effective UID is not the root user. Are you using sudo? SU? Exiting...")
	sys.exit()

# Set the apt command used for the rest of the script
if os.path.exists("/usr/bin/apt"): aptcommand = "apt"
elif os.path.exists("/usr/bin/aptitude"): aptcommand = "aptitude"
else: aptcommand = "apt-get"

#-------------- BRUTE FORCE METHOD
if len(sys.argv) > 1 and "brute" in sys.argv:
	bruteforce = boldinput("You wanna brute force this cheese? (y/N): ")
	if bruteforce == "y":
		while True:
			call("ufw enable")
	else:
		fail("Chose not to brute force the cheese.")
		sys.exit()

#-------------- DISTRIBUTION DETECT
# Old distribution choice menu
#print("\n" + color.bold)
#print("[1] Ubuntu 14.04 Trusty Tahr (default)")
#print("[2] Debian 7 Wheezy")
#print("[3] Ubuntu 16.04 Xenial Xerus")
#print("[4] Debian 8 Jessie")
#print("\n")
#distribution = boldinput("Input distribution: ")
distributions = {1:"trusty",2:"wheezy",3:"xenial",4:"jessie"}
if os.path.exists("/usr/bin/lsb_release"):
	green("LSB_Release was found")
	lsb = str(checkoutput("lsb_release -a"))
	if "Ubuntu" in lsb:
		if "14" in lsb:
			distribution = 1
			green("Running on Ubuntu 14 Trusty")
		elif "16" in lsb:
			distribution = 3
			green("Running on Ubuntu 16 Xenial")
	elif "Debian" in lsb:
		if "wheezy" in lsb:
			distribution = 2
			green("Running on Debian 7 Wheezy")
		elif "jessie" in lsb:
			distribution = 4
			green("Running on Debian 8 Jessie")
	else:
		fail("Unable to determine distribution or distribution not supported. Exiting...")
		sys.exit()
elif os.path.exists("/etc/debian_version"):
	green("Debian version was found")
	debian_version = open("/etc/debian_version","r")
	versionnumber = str(debian_version.readline())
	if "7" in versionnumber:
		distribution = 2
		green("Running on Debian 7 Wheezy")
	elif "8" in versionnumber:
		distribution = 4
		green("Running on Debian 8 Jessie")
	else:
		fail("Unable to determine distribution or distribution not supported. Exiting...")
		sys.exit()
else:
	fail("Unable to determine distribution or distribution not supported. Exiting...")
	sys.exit()

if "skipapt" in sys.argv:
	warning("Skipping apt sections.")
else:
#-------------- APT SOURCES
# Consistently break APT, TODO
#	if distribution == 1:
#		sources = ["deb http://security.ubuntu.com/ubuntu/ trusty main restricted\n","deb http://security.ubuntu.com/ubuntu/ trusty-security universe\n","deb http://security.ubuntu.com/ubuntu/ trusty-security multiverse"]
#	elif distribution == 2:
#		sources = ["deb http://ftp.us.debian.org/debian wheezy main\n"]
#	elif distribution == 3:
#		sources = ["deb http://security.ubuntu.com/ubuntu/ xenial main restricted\ndeb http://security.ubuntu.com/ubuntu/ xenial-security universe restricted main\ndeb http://archive.ubuntu.com/ubuntu xenial main universe restricted multiverse\ndeb http://archive.ubuntu.com/ubuntu xenial-updates main restricted multiverse universe\ndeb http://security.ubuntu.com/ubuntu/ xenial-security multiverse"]
#	elif distribution == 4:
#		sources = ["deb http://ftp.us.debian.org/debian jessie main\n","deb http://security.debian.org/ jessie/updates main\n"]
#
# Move sources.list to backup
#	try:
#		shutil.move("/etc/apt/sources.list","/etc/apt/sources.list.old")
#		green("Sources.list moved to /etc/apt/sources.list.old")
#	except:
#		fail("Sources.list move failed.")
#
# Create a new sources.list and write the sources
#	try:
#		sourcelist = open("/etc/apt/sources.list","w+")
#		sourcelist.writelines(sources)
#		green("New sources have been written")
# Close sources.list
#		sourcelist.close()
#	except:
#		fail("Writing sources.list failed.")

#-------------- UNAUTHORIZED SOFTWARE
# Smack down the banhammer
	taboo = ["vuze","transmission-gtk","transmission-common","john","john-data","hydra-gtk","hydra","frost","ophcrack","nikto"]
	uninstall(taboo)

#-------------- PACKAGE UPDATES
# Try running aptitude update/upgrade
	try:
		bold("Updating repositories...")
		checkoutput("apt-get update -y ")
		bold("Updating packages...")
		checkoutput("apt-get upgrade -y ")
# Editable list to add new applications to
		autoinstall = ["clamav","nano","vim","ufw","unattended-upgrades","nmap","openssh-server"]
		install(autoinstall)
# Kind message to the user if it errors out
	except: 
		fail("Aptitude commands failed. Are you root? Sudo?")

#-------------- PACKAGE INSTALLATION
# Fun while loop to install apps through Aptitude
	while apps != "":
		apps = str(boldinput("Packages to install (separated by a space): ")).split()
		if str(apps) == "[]": break
		try:
			install(apps)
		except:
			fail("Install failed. Are you root? Ensure package name is correct.")

#-------------- RECONFIGURE PACKAGES
# Try enabling unattended upgrades
	call("dpkg-reconfigure --frontend=readline unattended-upgrades")

#-------------- DELETE USERS
# Try to open and print /etc/group and error out if it errors out
try:
	etcgroup = open("/etc/group","r")
	for line in etcgroup:
		blue(line)
	etcgroup.close()
except:
	fail("Opening /etc/group failed.")

# Loop to get users to delete
while deluser != "":
	deluser = boldinput("User to delete: ")
	if deluser == "": break
	try:
		call("deluser " + deluser + " --remove-home")
		call("delgroup " + deluser)
	except:
		fail("Deleting user failed. Does the user exist?")

#-------------- ADD USERS
# Accept user and group in one input
while adduser != "":
	adduser = boldinput("User name and group to add, separated by a space: ")
	if adduser == "": break
	usergroup = adduser.split()
	checkoutput("adduser " + str(usergroup[0]))
	if len(usergroup) > 1: checkoutput("usermod -a -G " + str(usergroup[1]) + " " + str(usergroup[0]))

#-------------- DEMOTE USERS
# Ask for users to demote
while demote != "":
	demote = boldinput("User to demote: ")
	if demote == "": break
	call("deluser " + demote + " adm")
	call("deluser " + demote + " admin")
	call("deluser " + demote + " sudo")
	call("deluser " + demote + " wheel")

#-------------- UFW FIREWALL
# Enable UFW/error trap
try:
	bold("Enabling UFW...")
	checkoutput("ufw enable")
	green("UFW enabled.")
except:
	fail("Enabling UFW failed. Are you root?")

# Add exceptions via loop
while exceptionport != "":
	exceptionport = boldinput("Enter exception ports (ex. '22/tcp'): ")
	if exceptionport == "": break
	try:
		checkoutput("ufw allow " + exceptionport)
		green("Allowed port " + exceptionport)
	except:
		fail("Adding exception failed.")

# Try to set default deny policy
try:
	checkoutput("ufw default deny incoming")
	green("UFW default policy set.")
except:
	fail("UFW default policy failed.")

#-------------- SYSCTL CONFIG
# Remove IPv6 config from sysctl, then append new config
try:
	checkoutput("grep -v disable_ipv6 /etc/sysctl.conf > /tmp/sysctl.temp")
	shutil.move("/tmp/sysctl.temp","/etc/sysctl.conf")
	sysctl = open("/etc/sysctl.conf","a+")
	sysctl.write("net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1")
	sysctl.close()
except:
	fail("SysCTL configuration failed.")

#-------------- IPV6 CONFIGURATION
# Try opening NMTUI and Unity Control Center to disable IPv6 in NetworkManager
try:
	call("nmtui")
except:
	warning("NMTui is not present. Continuing...")
	
try:
	bold("Set screen saver w/ password")
	bold("Set auto update options")
	checkoutput("unity-control-center")
except:
	warning("Unity control center is not present. Continuing...")

#-------------- SUDOERS.D CONFIGURATION
# Open visudo, then print sudoers.d listing and ask to edit
call("update-alternatives --config editor")
call("visudo")
for dirpath, dirnames, filenames in os.walk("/etc/sudoers.d/"):
	for filename in filenames:
		blue(filename)
while sudoers != "":
	sudoers = boldinput("Sudoers.d findings above, enter filename to edit: ")
	if sudoers == "": break
	call("nano /etc/sudoers.d/" + sudoers)

#-------------- LOGIN DEFINITIONS
# Remove comments and change parameters with sed in login.defs
try:
	checkoutput("sed -i -e 's/.*#.*/#/' /etc/login.defs")
	checkoutput("sed -i -e 's/.*PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs")
	checkoutput("sed -i -e 's/.*PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs")
	checkoutput("faillog -m 3")
# Line below breaks logins
#os.system("sed -i '1 i\auth required pam_tally.so per_user magic_root onerr=fail' /etc/pam.d/common-auth")
except:
	fail("Login definitions failed.")
	
#-------------- LIGHTDM CONFIGURATION
try:
	lightdmconf = open("/etc/lightdm/lightdm.conf","w+")
	lightdmconf.write("[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true\nautologin-user=")
	lightdmconf.close()
except:
	fail("LightDM configuration failed.")

#-------------- PASSWORDS
while confirm.lower() != "y":
	password = boldinput("Enter password to set for all users: ")
	confirm = boldinput("Confirm (y/N/c): ")
	if confirm.lower() == "c": break
	if confirm.lower() == "y":
		try:
			call("""cat /etc/passwd | grep ':' | sed -e 's/:.*$/:/p' | sed -e '/cyberpatriot/d'  | sed -e '/CyberPatriot/d' | sed -e '/nobody/d' | sed "s/$/""" + password + """/" | chpasswd""")
		except:
			fail("Changing passwords failed.")
			break

#-------------- CRONTABS
# Original prompt
#call("crontab -e")
#admin = boldinput("Enter the name of the default login user: ")
#call("crontab -u " + admin + " -e")
for file in os.listdir("/var/spool/cron/crontabs/"):
	call("nano /var/spool/cron/crontabs/" + str(file))

#-------------- NETCAT
# Run ps -aux and only show lines with nc or netcat
underline("These are all processes found containing the words 'nc' or 'netcat'.")
for line in checkoutput("ps -aux").split("\n"):
	if "netcat" in line or "nc" in line:
		print(str(line))
boldinput("Paused, strike return to continue")

#-------------- SERVERS
packagelist = str(checkoutput("dpkg --list"))
### OPENSSH
if "openssh-server" in packagelist:
	bold("OpenSSH server is installed.")
# Call sed to remove comments, then edit in the new parameters
	try:
		checkoutput("sed -i -e 's/.*#.*/#/' /etc/ssh/sshd_config")
		green("Removed comments.")
		checkoutput("sed -i -e 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config")
		green("Forced SSHv2.")
		checkoutput("sed -i -e 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
		green("Disabled root login.")
		checkoutput("sed -i -e 's/.*LoginGraceTime*.*/LoginGraceTime 30/g' /etc/ssh/sshd_config")
		green("Reduced login grace time.")
		checkoutput("sed -i -e 's/.*StrictModes.*/StrictModes yes/' /etc/ssh/sshd_config")
		green("Required strict modes.")
		checkoutput("sed -i -e 's/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config")
		green("Disabled empty passwords.")
		checkoutput("sed -i -e 's/.*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config")
		green("Disabled X forwarding.")
		checkoutput("sed -i -e 's/.*PrintMotd no.*/PrintMotd yes/g' /etc/ssh/sshd_config")
		green("Enabled MOTD.")
		green("OpenSSH configuration done.")
	except:
		fail("SSHD config failed.")
else: warning("OpenSSH server is not installed.")
### DROPBEAR
if "dropbear" in packagelist:
	warning("Dropbear is installed.")
	dropbear = boldinput("Remove Dropbear? (y/N): ")
	if dropbear == "y": uninstall(["dropbear"])
else: bold("Dropbear is not installed.")
### MYSQL
if "mysql-server" in packagelist:
	bold("MySQL is installed.")
	try:
# Allow only local access to MySQL in my.cnf
		checkoutput("sed -i -e 's/.*bind-address=.*/bind-address=127.0.0.1/' /etc/mysql/my.cnf")
		green("Bind address set.")
		checkoutput("sed -i -e 's/.*local-infile=.*/local-infile=0/' /etc/mysql/my.cnf")
		green("Disabled use of local files.")
		call("mysql_secure_installation")
		restartservice("mysql")
		green("MySQL configuration done.")
	except:
		fail("MySQL configuration failed.")
else:
	bold("MySQL is not installed.")
### APACHE
if "apache2" in packagelist:
	bold("Apache2 is installed.")
	try:
		checkoutput("sed -i -e 's/.*#.*/#/' /etc/apache2/conf-enabled/security.conf")
		green("Removed comments.")
		checkoutput("sed -i -e 's/.*ServerTokens.*/#/' /etc/apache2/conf-enabled/security.conf")
		green("Deleted ServerTokens directive.")
		checkoutput("sed -i -e 's/.*ServerSignature.*/#/' /etc/apache2/conf-enabled/security.conf")
		green("Deleted ServerSignature directive.")
		checkoutput("echo 'ServerTokens Prod' >> /etc/apache2/conf-enabled/security.conf")
		green("Set ServerTokens to production mode.")
		checkoutput("echo 'ServerSignature Off' >> /etc/apache2/conf-enabled/security.conf")
		green("Disabled ServerSignature.")
		restartservice("apache2")
		green("Apache2 configuration done.")
	except:
		fail("Apache2 configuration failed.")
### SAMBA
if os.path.exists("/usr/sbin/smbd"):
	bold("Samba is installed.")
	try:
		bold("Assuming Samba should be nuked.")
		disableservice("smbd")
		disableservice("samba")
		
		# Disable anonymous samba access
		bold("Disabling guest access to samba shares")
		checkoutput("sed -i '/guest ok/d' /etc/samba/smb.conf")
		checkoutput("sed -i '/public/d' /etc/samba/smb.conf")
	except:
		fail("Samba configuration failed.")
	green("Samba configuration done.")
### PHP
if os.path.exists("/usr/bin/php"):
	bold("PHP is installed.")
	######## PHP CONFIGURATION HERE
	green("PHP configuration done.")
	
### FTP
	######## FTP CONFIGURATION HERE
	
### NFS
	######## NFS CONFIGURATION HERE
	
### VNC
	######## VNC CONFIGURATION HERE

#-------------- MEDIA FILES
if "skipmedia" in sys.argv:
	warning("Skipping media file search.")
else:
	bold("Finding MP3s...")
	call("find / -iname '*.mp3' > /root/mediafiles.txt")
	bold("Finding JPEGs...")
	call("find / -iname '*.jp*g' >> /root/mediafiles.txt")
	bold("Finding PNGs...")
	call("find / -iname '*.png' >> /root/mediafiles.txt")
	bold("Finding GIFs...")
	call("find / -iname '*.gif' >> /root/mediafiles.txt")
	bold("Finding AVIs...")
	call("find / -iname '*.avi' >> /root/mediafiles.txt")
	bold("Finding BMPs...")
	call("find / -iname '*.bmp' >> /root/mediafiles.txt")
	bold("Finding OGGs...")
	call("find / -iname '*.og*' >> /root/mediafiles.txt")

	mediafiles = checkoutput("grep /usr/ /root/mediafiles.txt -v")
	mediafiletxt = open("/root/mediafiles.txt","w+")
	mediafiletxt.write(mediafiles)
	mediafiletxt.close()
	green("Found media files written to /root/mediafiles.txt")

#-------------- LOCK ACCOUNTS
try:
	checkoutput("passwd -dl root")
	green("Locked root account.")
except:
	warning("Could not lock the root account.")

#-------------- USER IDS
etcpasswd = open("/etc/passwd","r")
for line in etcpasswd:
	if ":0:" in line and "root" not in line:
		warning(line + "A user was found with UID 0, they should be edited or removed")

#-------------- PERMISSIONS

#-------------- MALWARE
if "skipav" in sys.argv:
	warning("Skipping clamav scan.")
else:
	bold("Scanning for infected files...")
	call("clamscan -ir / -l /root/clamscan.log")
	green("Scan results written to /root/clamscan.log")
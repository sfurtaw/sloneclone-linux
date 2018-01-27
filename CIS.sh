#!/bin/bash
# Align system to CIS benchmark
# Team 'Slone clones in the danger zone we swear we know what we are doing'

# Disable exit-on-error
set -e

rm -rf /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.1 Disable cramfs
echo "install cramfs /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.2 Disable freevxfs
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.3 Disable jffs2
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.4 Disable hfs
echo "install hfs /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.5 Disable hfsplus
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.6 Disable squashfs
echo "install squashfs /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.1.7 Disable udf
echo "install udf /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 1.1.20 Set sticky bit on all world-writeable directories
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo 1.1.21 Disable auto mount
systemctl disable autofs

echo 1.4.1 Set bootloader config permissions
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

echo 1.5.1 Restrict core dumps
mkdir /etc/security/limits.d
echo "* hard core 0" > /etc/security/limits.d/coreDumps
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

echo 1.5.3 Enable ASLR
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2

echo 1.7.1.1 Add MOTD
echo "kindly dingus yourself" > /etc/motd

echo 1.7.1.2 Configure local login banner
echo "whom'st'd've'd?" > /etc/issue

echo 1.7.1.3 Configure remote login banner
echo "why the FRICK chick fil a closed on sunday" > /etc/issue.net

echo 1.7.1.4 Configure /etc/motd permissions
chown root:root /etc/motd
chmod 644 /etc/motd

echo 1.7.1.5 Configure /etc/issue permissions
chown root:root /etc/issue
chmod 644 /etc/issue

echo 1.7.1.6 Configure /etc/issue.net permissions
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

echo 2.1.10 Disable xinetd
systemctl disable xinetd

echo 2.2.3 Disable Avahi Server
systemctl disable avahi-daemon

echo 2.2.4 Disable CUPS
systemctl disable cups

echo 2.2.5 Disable DHCP server
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6

echo 2.2.6 Disable LDAP
systemctl disable slapd

echo 2.2.7 Disable NFS and RPC
systemctl disable nfs-kernel-server
systemctl disable rpcbind

echo 2.2.8 Disable DNS server
systemctl disable bind9

echo 2.2.9 Disable FTP service
systemctl disable vsftpd

echo 2.2.11 Disable IMAP and POP3 servers
systemctl disable dovecot

echo 2.2.13 Disable proxy server
systemctl disable squid

echo 2.2.14 Disable SNMP daemon
systemctl disable snmpd

echo 2.2.16 Disable rsync
systemctl disable rsync

echo 2.2.17 Disable NIS server
systemctl disable nis

echo 2.3.1 Remove NIS client
apt remove nis

echo 2.3.2 Remove rsh client
apt remove rsh-client rsh-redone-client

echo 2.3.3 Remove talk client
apt remove talk

echo 2.3.4 Remove telnet client
apt remove telnet

echo 2.3.5 Remove LDAP client
apt remove ldap-utils

echo 3.1.1 Disable IP forwarding
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

echo 3.1.2 Disable packet redirect sending
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

echo 3.2.2 Disable ICMP redirects
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

echo 3.2.3 Disable secure ICMP redirects
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

echo 3.2.4 Log suspicious packets
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

echo 3.2.5 Disable broadcast ICMP
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

echo 3.2.6 Ignore bogus ICMP requests
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

echo 3.2.7 Disable reverse path filtering
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

echo 3.2.8 Enable TCP SYN cookies
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo 3.4.1 Install TCP wrappers
apt install tcpd

echo 3.5.1 Disable DCCP
echo "install dccp /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 3.5.2 Disable SCTP
echo "install sctp /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 3.5.3 Disable RDS
echo "install rds /bin/true" >> /etc/modprobe.d/CISbenchmark.conf

echo 3.5.4 Disable TIPC
echo "install tipc /bin/true" >> /etc/modprobe.d/CISbenchmark.conf


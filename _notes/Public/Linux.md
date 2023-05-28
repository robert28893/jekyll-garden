## Content
[[#Welcome to Linux]]
[[#Linux virtualization]]
[[#Remote connectivity]]
[[#Archive management]]
[[#Automated administration]]
[[#Emergency tools: building a system recovery device]]
[[#Web servers]]
[[#Networked file sharing]]
[[#Securing your web server]]
[[#Securing network connections: Creating a VPN or DMZ]]
[[#System monitoring: Working with log files]]
[[#Sharing data over a private network]]
[[#Troubleshooting system performance issues]]
[[#Troubleshooting network issues]]
[[#Troubleshooting peripheral devices]]
[[#DevOps tools: Deploying a scripted server environment using Ansible]]

## Welcome to Linux
### Basic survival skills
1. The Linux file system
/etc: Program configuration files
/var: Frequently changing content (log files ...)
/home: User account files
/sbin: system binary files
/bin: User binary files
/lib: shared libraries
/usr: Third-party binaries
### Getting helps
1. Man files
```sh
man man
```

2. Info
Hiển thị danh sách các lệnh và cách dùng
```sh
info
```

## Linux virtualization
### Working with VirtualBox
1. Install virtualbox
```sh
sudo apt update
sudo apt install virtualbox
```

2. Defining a virtual machine
Setup rams, vdi

3. Installing an operating system
(1) Download ISO file chứa bản ubuntu server
(2) Boot VM bằng file ISO
(3) Cài os
(4) Bật VM và chạy os
(5) Cấu hình network => bridge
(6) Remove DVD from the drive

4. Cloning and sharing a virtualbox VM
```sh
vboxmanage list vms
vboxmanage clonevm --register Kali-Linux-template --name newkali
vboxmanage export website-project -o website.ova # export thành file để gửi hoặc sao lưu
vboxmanage import website.ova # import file
```

### Working with Linux containers (LXC)
1. Install lxc
```sh
sudo apt update
sudo apt install lxc lxctl lxc-templates
```

2. Creating a container
```sh
sudo lxc-create -n myContainer -t ubuntu
# username va password mac dinh la 'ubuntu'
# sau khi login doi lai password bang lenh passwd
sudo lxc-start -d -n myContainer
sudo lxc-ls --fancy # list container
sudo lxc-attach -n myContainer # attach to container
```

## Remote connectivity

1. ssh
```sh
dpkg -s openssh-client # check status of ssh package

## add ssh pubkeys
mkdir ~/.ssh
echo 'pubkey content' >> ~/.ssh/authorized_keys

cat ~/.ssh/id_rsa.pub | ssh ubuntu@10.0.3.69 "cat >> ~/.ssh/authorized_keys" # cách khác để copy pubkey

ssh-copy-id -i .ssh/id_rsa.pub ubuntu@10.0.3.69 # dùng lệnh này để copy public key lên authorized_keys của server

ssh ubuntu@10.0.3.69
```

2. scp
```sh
ssh-copy-id -i .ssh/id_rsa.pub ubuntu@10.0.3.142
```

3. ps
```sh
ps --help all
ps aux
ps -e u
```

## Archive management
### Why archive?
Archive là tập hợp gồm nhiều folders và files => Dễ quản lý, backup, copy, gửi

### Archiving using tar
```sh
tar -cvf archivename.tar *.mp4
tar -czvf archivename.tar.gz /home/myuser/Videos/*.mp4
split -b 1G archivename.tar.gz "archivename.tar.gz.part"
cat archivename.tar.gz.part* > archivename.tar.gz
tar czvf - --one-file-system / /usr /var \
--exclude=/home/andy/ | ssh username@10.0.3.141 \
"cat > /home/username/workstation-backup-Apr-10.tar.gz"
# --one-file-system: loai bo cac file system
# --exclude: loai bo duong dan bat ky
```

Find
```sh
find /var/www/html/ -iname <1> "*.mp4" -exec tar \
-rvf videos.tar {} \;
locate *video.mp4 # tim cac file co ten video.mp4
```

### Archiving partitions with dd
```sh
dd if=/dev/sda of=/home/username/sdadisk.img # tạo .img archive của /dev/sda và luu ra thu muc home
dd if=/dev/sda2 of=/home/username/partition2.img bs=4096 # set block size => so bytes 1 lan copy
dd if=sdadisk.img of=/dev/sdb # restoring

```

### Synchronizing archives with rsync
```sh
rsync -av * username@10.0.3.141:syncdirectory
```

## Automated administration

Linux keeps user account and authentication information in plain text files (named passwd, group, shadow, and gshadow) in the /etc/ directory.

### Scripting with Bash
```sh
#!/bin/sh
cd /var/backups || exit 0
for FILE in passwd group shadow gshadow; do
test -f /etc/$FILE || continue
cmp -s $FILE.bak /etc/$FILE && continue
cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done
```
### Backing up data to AWS S3

```sh
pip3 install --upgrade --user awscli
aws configure # cấu hình aws
aws s3 ls # list các buckets
aws s3 mb s3://linux-bucket3040 # tạo bucket
aws s3 sync /home/username/dir2backup s3://linux-bucket3040 # tương tụ rsync
```

### Scheduling regular backups with cron
```sh
ls /etc | grep cron
#anacrontab
#cron.d
#cron.daily
#cron.hourly
#cron.monthly
#crontab
#cron.weekly
crontab -l # list crontab của user
crontab -e # chỉnh sửa crontab
# đường dẫn crontab lưu tại /var/spool/cron/crontabs/
crontab -u <user1> -l | crontab -u <user2> # copy crontab from user1 to user2
```

### Scheduling irregular backups with anacrontab

sửa file /etc/anacrontab
```sh
# /etc/anacrontab: configuration file for anacron
# See anacron(8) and anacrontab(5) for details.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/
usr/sbin:/usr/bin

HOME=/root
LOGNAME=root
# These replace cron's entries
1 5 cron.daily run-parts --report /etc/cron.daily # chạy 1 ngày 1 lần sau boot 5 phút
7 10 cron.weekly run-parts --report /etc/cron.weekly # chạy 7 ngày 1 lần sau boot 10 phút
@monthly 15 cron.monthly run-parts --report /etc/cron.monthly

1 10 myBackupJob /home/myname/backup.sh # 1 ngày 1 lần sau boot 10 phút

# log đươc lưu ở /var/spool/anacron/
```

### Scheduling regular backups with systemd timers
```sh
systemctl list-timers --all
```

/etc/systemd/system/site-backup.service
```sh
[Unit]
Description=Backup Apache website

[Service]
Type=simple
ExecStart=/home/username/site-backup.sh

[Install]
WantedBy=multi-user.target
```

/etc/systemd/system/site-backup.timer
```sh
[Unit]
Description=Backup Apache website - daily

[Timer]
OnCalendar=*-*-* 5:51:00 
Unit=site-backup.service

[Install]
WantedBy=multi-user.targe
```

```sh
systemctl start site-backup.timer
systemctl enable site-backup.timer
systemctl is-enabled backup.timer # check enabled
systemctl is-active site-backup.timer # check actived
systemctl daemon-reload # reload sau khi sua config
```

## Emergency tools: building a system recovery device

![[Pasted image 20221115175939.png]]

### Working in recovery/rescue mode
1. The GRUB bootloader

![[Pasted image 20221115180246.png]]

2. Using recovery mode on Ubuntu

### Building a live-boot recovery drive
```sh
isohybrid systemrescuecd-x86-5.0.2.iso
lsblk
umount /dev/sdb
dd bs=4M if=systemrescuecd-x86-5.0.2.iso \
of=/dev/sdb && sync
```

### Putting your live-boot drive to work
1. Testing system memory
2. Damaged partitions
3. Recovering files from a damged file system
```sh
mkdir /run/temp-directory
mount /dev/sdc1 /run/temp-directory
apt install gddrescue
ddrescue -d /dev/sdc1 /run/usb-mount/sdc1-backup.img \
/run/usb-mount/sdc1-backup.logfile
dd if=backup.img of=/dev/sdd
```

### Password recovery: Mouting a file system using chroot

```sh
passwd username # neu co 1 tai khoan admin thi dung lenh sau de dat lai password

# neu quen het thi dung chroot
mkdir /run/mountdir/
mount /dev/sdb1 /run/mountdir/
chroot /run/mountdir/
```

## Web servers
### Building a LAMP server
The letters LAMP stand for Linux, the Apache web server
administration software, either the MySQL or MariaDB database engine, and the PHP
server-side scripting language (or, alternatively, Perl or Python).

```sh
apt install lamp-server^
```

### Manual setting up an Apache web server
```sh
apt install apache2
```

/etc/apache2/sites-available/000-default.conf
```sh
DocumentRoot /var/www/html
```

### Installing an SQL database
```sh
apt update
apt install mariadb-server
systemctl status mysql
mysql_secure_installation
```

Set quyền cho user thường login vào mysql root
```sql
mysql -u root -p
SET PASSWORD = PASSWORD('your-password');
update mysql.user set plugin = 'mysql_native_password' where User='root';
FLUSH PRIVILEGES;
```

Create db và user
```sql
CREATE DATABASE wikidb;
CREATE USER 'mw-admin'@'localhost' IDENTIFIED BY 'mypassword';
GRANT ALL PRIVILEGES ON wikidb.* TO 'mw-admin'@'localhost' IDENTIFIED BY 'mypassword';
FLUSH PRIVILEGES;
```

### Installing PHP

1. Installing
```sh
apt install php
apt install libapache2-mod-php
systemctl restart apache2
```

2. Testing
```sh
vim /var/www/html/testmyphp.php
```

```php
<?php
phpinfo();
?>
```

browser -> [http://10.0.3.243/testmyphp.php](http://10.0.3.243/testmyphp.php)

### Installing and configuring MediaWiki
1. Download and unpack the MediaWiki archive package
```sh
wget https://releases.wikimedia.org/mediawiki/1.30/mediawiki-1.30.0.tar.gz
tar xzvf mediawiki-1.30.0.tar.gz
mv mediawiki-1.30.0/ /var/www/html/mediawiki
```

browser -> [http://10.0.3.243/mediawiki/index.php](http://10.0.3.243/mediawiki/index.php)

2. Identify and install necessary software extensions

```sh
apt search mbstring
apt search xml | grep php
apt install php7.2-mbstring php7.2-xml
systemctl restart apache2
```

```sh
apt install php-mysql php-apcu php-imagick
systemctl restart apache2
```

3. Connect MediaWiki to your MariaDB database
browser -> [http://10.0.3.243/mediawiki/index.php](http://10.0.3.243/mediawiki/index.php)
điền các thông tin db -> done
Download file LocalSettings.php
```sh
scp LocalSettings.php ubuntu@10.0.3.243:/home/ubuntu/
cp /home/ubuntu/LocalSettings.php /var/www/html/mediawiki/
```

4. Run and test the installation.
browser -> [http://10.0.3.243/mediawiki/index.php](http://10.0.3.243/mediawiki/index.php)

## Networked file sharing

### Installing Nextcloud using snaps
```sh
apt install snapd
snap install nextcloud
```

### Installing Nextcloud manaually
1. Installing packages
```sh
apt install apache2 mariadb-server libapache2-mod-php7.0 \
php7.0-gd php7.0-json php7.0-mysql php7.0-curl php7.0-mbstring \
php7.0-intl php7.0-mcrypt php-imagick php7.0-xml php7.0-zip

sudo apt install apache2 mariadb-serve libapache2-mod-php7.2 php7.2-gd php7.2-json php7.2-mysql php7.2-curl php7.2-mbstring php7.2-intl php7.2-zip php-imagick php7.2-xml
```

2. Configuring Apache
```sh
a2enmod rewrite
a2enmod headers
```

/etc/apache2/sites-available/nextcloud.conf
```
Alias /nextcloud "/var/www/nextcloud/"

<Directory /var/www/nextcloud/>
	Options +FollowSymlinks
	AllowOverride All
	
	<IfModule mod_dav.c>
		Dav off
	</IfModule>

	SetEnv HOME /var/www/nextcloud
	SetEnv HTTP_HOME /var/www/nextcloud
	
</Directory>
```

add Content to /etc/apache2/sites-available/000-default.conf
```
<VirtualHost *:443>
	ServerName bootstrap-it.com
	DocumentRoot /var/www/nextcloud
	ServerAlias bootstrap-it.com/nextcloud
</VirtualHost>
```

```sh
ln -s /etc/apache2/sites-available/nextcloud.conf /etc/apache2/sites-enabled/nextcloud.conf
```

3. Downloading and unpacking Nextcloud

```sh
wget https://download.nextcloud.com/server/releases/nextcloud-13.0.12.tar.bz2
tar xjf nextcloud-13.0.12.tar.bz2
cp -r nextcloud /var/www/
chown -R www-data:www-data /var/www/nextcloud/
systemctl restart apache2
journalctl | tail
```

browser -> [http://10.0.3.243/nextcloud](http://10.0.3.243/nextcloud)

4. Nextcloud administration

create DB and user
```sql
mysql -u root -p
CREATE DATABASE nextcloud;
CREATE USER 'oc_admin'@'localhost' IDENTIFIED BY 'mypassword';
GRANT ALL PRIVILEGES ON nextcloud.* TO 'oc_admin'@'localhost' IDENTIFIED BY 'mypassword';
```

browser -> [http://10.0.3.243/nextcloud](http://10.0.3.243/nextcloud)

Điền các thông tin: tài khoản admin, db => thành công sẽ gen ra file config bên dưới

/var/www/nextcloud/config/config.php

```php
<?php
$CONFIG = array (
	'instanceid' => 'ociu535bqczx',
	'passwordsalt' => '',
	'secret' => '',
	'trusted_domains' =>
	array (
		0 => '10.0.3.243',
	),
	'datadirectory' => '/var/www/nextcloud/data',
	'overwrite.cli.url' => 'http://10.0.3.243/nextcloud',
	'dbtype' => 'mysql',
	'version' => '12.0.0.29',
	'dbname' => 'nextcloud',
	'dbhost' => 'localhost',
	'dbport' => '',
	'dbtableprefix' => 'oc_',
	'dbuser' => 'oc_admin',
	'dbpassword' => 'mypassword',
	'installed' => true,
);
```

```sh
cd /var/www/nextcloud
sudo -u www-data php occ -h
sudo -u www-data php occ list
```

## Securing your web server
### Controlling network access
1. Configuring a firewall

- FIREWALLD
```sh
apt update
apt install firewalld
firewall-cmd --state
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --list-services
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --remove-port=22/tcp
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.5" port protocol="tcp" port="22" accept'
```

- UNCOMPLICATED FIREWALL ( UFW )

/etc/default/ufw
```sh
# Set to yes to apply rules to support IPv6 (no means only IPv6 on loopback
# accepted). You will need to 'disable' and then 'enable' the firewall for
# the changes to take affect.
IPV6=no # sua yes -> no
```

```sh
apt install ufw
ufw allow ssh
ufw enable
ufw disable
ufw delete 2
ufw allow from 10.0.3.1 to any port 22
ufw enable
ufw status
ufw deny 22/tcp
```

- RECOVERING A LOCKED VM
```sh
lxc-stop -n your-container-name
chroot /var/lib/lxc/your-container-name/rootfs/
ufw disable
exit
lxc-start -d -n your-container-name
``` 

### Encrypting data in transit
1. Generating certificates using Let’s Encrypt
```sh
apt update
apt install snapd
sudo mount -t tmpfs tmpfs /sys/kernel/security/
sudo systemctl restart snapd
sudo snap install core; sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
sudo certbot --apache # get a certificate and edit your apache configuration automatically
sudo certbot certonly --apache # chỉ get certificate
```

### Hardening the authentication process

/etc/ssh/sshd_config
```sh
PermitRootLogin no # Avoid logging in to servers as the root user
PasswordAuthentication no # With no password authentication,
# users will be forced to use key pairs:
```

```sh
systemctl restart sshd
```

1. System groups and the principle of least privilege
```sh
groupadd app-data-group
usermod -aG app-data-group otheruser
```

/etc/group
```
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
```

### Auditing system resources
1. Scanning for open ports
```sh
netstat -npl
ss -o state established '( dport = :ssh or sport = :ssh )'
```

2. Scanning for active services
```sh
systemctl list-unit-files --type=service --state=enabled

systemctl stop haveged
systemctl disable haveged
```

3. Searching for installed sofware
```sh
dpkg --list
apt-get remove packageName
```

## Securing network connections: Creating a VPN or DMZ
### Building an OpenVPN tunnel
1. Configuring an OpenVPN server
- Enable firewall
```sh
ufw enable
ufw allow 22
ufw allow 1194 # default OpenVPN port
```

- Permit internal routing between network interfaces on the server
/etc/sysctl.conf
```
net.ipv4.ip_forward=1
```

```sh
sysctl -p # load the new setting
```

- Install openvpn and easy-rsa
```sh
apt install openvpn -y
apt install easy-rsa -y
```

- Generating encryption keys
```sh
cp -r /usr/share/easy-rsa/ /etc/openvpn
cd /etc/openvpn/easy-rsa
cp vars.example vars
```

/etc/openvpn/easy-rsa/vars
```
set_var EASYRSA_REQ_COUNTRY     "CA"
set_var EASYRSA_REQ_PROVINCE    "ON"
set_var EASYRSA_REQ_CITY        "Toronto"
set_var EASYRSA_REQ_ORG         "Bootstrap IT"
set_var EASYRSA_REQ_EMAIL       "info@bootstrap-it.com"
set_var EASYRSA_REQ_OU          "IT"
```

```sh
# Generating a 2048 bit RSA private key
cd /etc/openvpn/easy-rsa/
./easyrsa init-pki
./easyrsa build-ca
./easyrsa build-server-full server nopass
./easyrsa gen-dh

cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/server/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/server/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/server/
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/server/

cd /etc/openvpn/server
openvpn --genkey tls-auth ta.key # gen file key dung de auth. can copy file nay ve client de cau hinh o client
```

- Preparing client encryption keys
```sh
cd /etc/openvpn/easy-rsa/
./easyrsa build-client-full client nopass

cp /etc/openvpn/easy-rsa/pki/private/client.key /home/robert/
cp /etc/openvpn/easy-rsa/pki/issued/client.crt /home/robert/
cp /etc/openvpn/easy-rsa/pki/ca.crt /home/robert/
cp /etc/openvpn/server/ta.key /home/robert

chown robert:robert /home/robert/{ca.crt,client.crt,client.key,ta.key}
```

- Config server
```sh
cat /usr/share/doc/openvpn/examples/sample-config-files/server.conf > /etc/openvpn/server/server.conf
```

/etc/openvpn/server/server.conf
```
port 1194
# TCP or UDP server?
proto tcp
;proto udp
;dev tap
dev tun
ca ca.crt
cert server.crt
key server.key # This file should be kept secret
dh dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
;comp-lzo
port-share localhost 80
user nobody # Minimizes privileged system exposure
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn.log # Writes session logs to /etc/openvpn/openvpn.log
;log-append openvpn.log
verb 3 # Outputs verbosity, which can go as high as 9
;explicit-exit-notify 1 # comment nếu proto là tcp
tls-auth ta.key 0
```

```sh
sudo systemctl -f enable openvpn-server@server.service
sudo systemctl start openvpn-server@server.service
ip addr
```

2. Configuring an OpenVPN Client

```sh
apt install openvpn
cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf \
/home/robert/vpn-my-ubuntu
```

/home/robert/vpn-my-ubuntu/client.conf
```sh
client
;dev tap
dev tun
proto tcp
remote 192.168.1.38 1194
resolv-retry infinite
used to access the VPN server
nobind
user nobody
group nogroup
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
verb 3
remote-cert-tls server
tls-auth ta.key 
```

Copy config files
```sh
cd /home/robert/vpn-my-ubuntu
scp robert@192.168.1.38:/home/robert/ca.crt .
scp robert@192.168.1.38:/home/robert/client.crt .
scp robert@192.168.1.38:/home/robert/client.key .
scp robert@192.168.1.38:/home/robert/ta.key .
```

Start vpn client
```sh
cd /home/robert/vpn-my-ubuntu
openvpn --tls-client --config client.conf
```

### Building intrusion-resistant networks
1. Demilitarized zones (DMZs)
![[Pasted image 20221214172759.png]]

One simple implementation of a DMZ, is to use a single server as a router to redirect traffic between the internet and two internal networks. One of the networks might contain backend databases or the workstations and laptops used in your office. This network will be heavily protected by tight access rules. The other network will enjoy fairly direct and easy access to the outside world and might include publicfacing resources like web servers.

2. Using iptables

a. Types of Chains
- **Input** – This chain is used to control the behavior for incoming connections. For example, if a user attempts to SSH into your PC/server, iptables will attempt to match the IP address and port to a rule in the input chain.
- **Forward** – This chain is used for incoming connections that aren’t actually being delivered locally. Think of a router – data is always being sent to it but rarely actually destined for the router itself; the data is just forwarded to its target. Unless you’re doing some kind of routing, NATing, or something else on your system that requires forwarding, you won’t even use this chain.
- **Output** – This chain is used for outgoing connections. For example, if you try to ping howtogeek.com, iptables will check its output chain to see what the rules are regarding ping and howtogeek.com before making a decision to allow or deny the connection attempt.

b. Policy Chain Default Behavior
- ACCEPT means that the default policy for that chain, if there are no matching rules, is to allow the traffic. More times than not, you’ll want your system to accept connections by default. By defaulting to the **ACCEPT** rule, you can then use iptables to deny specific IP addresses or port numbers, while continuing to accept all other connections. 

- DROP does the opposite. If you would rather deny all connections and manually specify which ones you want to allow to connect, you should change the default policy of your chains to **DROP**. Doing this would probably only be useful for servers that contain sensitive information and only ever have the same IP addresses connect to them.

c. Connection-specific Responses

**Accept** – Allow the connection.

**Drop** – Drop the connection, act like it never happened. This is best if you don’t want the source to realize your system exists.

**Reject** – Don’t allow the connection, but send back an error. This is best if you don’t want a particular source to connect to your system, but you want them to know that your firewall blocked them.

```sh
iptables -L # list chains 
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP # apend rule to chain. Block SSH connections from 10.10.10.10
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -m state --state NEW,ESTABLISHED -j ACCEPT # allow ssh from 10.10.10.10
iptables -A OUTPUT -p tcp --sport 22 -d 10.10.10.10 -m state --state ESTABLISHED -j ACCEPT # khong cho mo ket noi ssh toi 10.10.10.10 nhung cho phep send back ban ghi
```

3. Creating a DMZ using iptables

Designation|Purpose
-----------|-------
eth0|Connected to the internet
eth1|Connected to the DMZ
eth2|Connected to the local private network

```sh
iptables -A FORWARD -i eth1 -o eth2 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT # forward packets from eth1 to eth2
iptables -A FORWARD -i eth2 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A PREROUTING -p tcp -i eth0 -d 54.4.32.10 \
--dport 80 -j DNAT --to-destination 192.168.1.20 # add rule vào nat table. packets tới ip 54.4.32.10 port 80 sẽ được route sang ip 192.168.1.20
```

4. Creating a DMZ using Shorewall
```sh
apt install shorewall
```

Config files in /etc/shorewall/

Filename|Purpose|Required
--------|-------|--------
zones|Declares the network zones you want to create|Yes
interfaces|Defines which network interfaces will be used for specified zones|Yes
policy|Defines high-level rules controlling traffic between zones|Yes
rules|Defines exceptions to the rules in the policy file|No
masq|Defines dynamic NAT settings|No
stoppedrules|Defines traffic flow while Shorewall is stopped|No
params|Sets shell variables for Shorewall|No
conntrack|Exempts specified traffic from Netfilter connection tracking|No

```sh
man shorewall-rules # man shorewall- + ten file trong bang tren
```

/etc/shorewall/zones
```sh
fw firewall
net ipv4
dmz ipv4
loc ipv4
```

/etc/shorewall/interfaces
```sh
net eth0 detect dhcp,nosmurfs,routefilter,logmartians
dmz eth1 detect dhcp
loc eth2 detect dhcp
```

/etc/shorewall/policy
```sh
net all DROP
loc net ACCEPT
fw all ACCEPT
all all
REJECT
```

/etc/shorewall/rules
```sh
ACCEPT all dmz tcp 80,443
ACCEPT net dmz tcp 22
ACCEPT loc dmz tcp 22
ACCEPT loc fw udp 53
Web(DNAT) net dmz:10.0.1.4
```

```sh
systemctl start shorewall
```

## System monitoring: Working with log files
### Working with system logs

![[Pasted image 20221227104837.png]]

![[Pasted image 20221227105041.png]]

1. Logging with journald
```sh
journalctl -n 20 # show 20 dòng cuối
journalctl -p emerg # piority = emerg. Các piority: debug, info, notice, warning, err, crit, alert
journalctl -f # follow
journalctl --since 15:50:00 --until 15:52:00
```

2. Logging with syslogd

/etc/rsyslog.d/50-default.conf

Filename|Purpose
--------|------
auth.log|System authentication and security events
boot.log|A record of boot-related events234
dmesg|Kernel-ring buffer events related to device drivers
dpkg.log|Software package-management events
kern.log|Linux kernel events
syslog|A collection of all logs
wtmp|Tracks user sessions (accessed through the who and last commands)

Syslogd priority levels
Level|Description
-----|------------
debug|Helpful for debugging
info|Informational
notice|Normal conditions
warn|Conditions requiring warnings
err|Error conditions
crit|Critical conditions
alert|Immediate action required
emerg|System unusable

### Managing log files
1. journald
This setting is controlled by the SystemMaxUse= and RuntimeMaxUse= settings in the /etc/systemd/journal.conf file.

2. syslogd

![[Pasted image 20221227160114.png]]

/etc/logrotate.conf

```sh
# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.
```

/etc/logrotate.d/apt
```sh
/var/log/apt/term.log {
  rotate 12
  monthly
  compress
  missingok
  notifempty
}

/var/log/apt/history.log {
  rotate 12
  monthly
  compress
  missingok
  notifempty
}
```

### Consuming large files
1. Using grep
```sh
cat /var/log/auth.log | grep 'Authentication failure'
cat /var/log/auth.log | grep -B 1 -A 1 failure # before 1 and after 1
grep -nr daemon # The n argument tells grep to include line information; the r argument returns recursive results.
```

2. Using awk
```sh
cat error.log | awk '$3 ~/[Warning]/' | wc
```

3. Using sed
```sh
cat error.log | awk '$3 ~/[Warning]/' | sed -n '$='
echo "hello world" | sed "s/world/fishtank/"
sed "s/^ *[0-9]* //g" numbers.txt
sed "s/^ *[0-9]* //" numbers.txt > new-numbers.txt
ls -l | sed -n '/^d/ p'
```

### Monitoring with intrusion detection
1. Setting up a mail server
2. Installing Tripwire
3. Configuring Tripwire
4. Generating a test Tripwire report

## Sharing data over a private network
### Sharing files through Network File System (NFS)

![[Pasted image 20221229113409.png]]
Step by step:
1 Install NFS on the server.
2 Define client access to server resources through the /etc/exports file.
3 Update NFS on the server.
4 Install NFS on the client.
5 Mount an NFS share.
6 Configure the NFS share to mount at boot time.
7 Open any firewalls you’ve got running (if necessary).

1. Setting up the NFS server

```sh
apt install nfs-kernel-server -y
```

/etc/exports
```sh
/home/robert       192.168.1.5(rw,sync,no_subtree_check,no_root_squash)
#/home 192.168.1.0/255.255.255.0(rw,sync) # for a subnet
```

- /home tells NFS that you want to expose the /home directory on the server
along with all its subdirectories. As long as you don’t unnecessarily expose sensi-
tive system or personal data, you’re free to expose any directories you like.
- 192.168.1.11 is the IP address of the NFS client you want to let in.
- rw assigns that client both read and write permissions on the files in the
exposed directories.
- sync maintains a stable environment by writing changes to disk before replying
to remote requests.
- The default NFS values include ro (read-only, meaning write operations are blocked)
and root_squash (remote client users aren’t permitted to perform actions on the
server as root, no matter what status they have on their own systems).
- no_root_squash: ngược lại với root_squash.

```sh
exportfs -ra
#The r flag tells exportfs to synchronize the file systems, and the flag a applies the action to all directories
exportfs # show info
```

Open firewall
```sh
ufw allow nfs
```

2. Setting up the client
```sh
apt install nfs-common -y
mkdir -p /mnt/home/robert
mount 192.168.1.37:/home/robert /mnt/home/robert
umount /mnt/home/robert # unmount
```

3. Mounting an NFS share at boot time
/etc/fstab
```sh
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-OFU5M9pBtzh1BaTlX9maa5Csj01a4iM0yJtHEKrSDjV1eqiAC0rVQFf0WX8Lg7FQ / ext4 defaults 0 1
# /boot was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/13ba54c2-4524-4c6c-b0d8-a63f9c94979c /boot ext4 defaults 0 1
/swap.img	none	swap	sw	0	0
```

Field|Purpose
-----|-------
File system|Identifies a device either by its boot-time designation (/dev/sda1, which can sometimes change) or, preferably, by its more reliable UUID.
Mount point|Identifies the location on the file system where the device is currently mounted.
Type|The file system type.
Options|Mount options assigned to the device.
Dump|Tells the (outdated) Dump program whether (1) or not (0) to back up the device.
Pass|Tells the fsck program which file system to check first at boot time. The root partition should be first (1).

/etc/fstab
```sh
192.168.1.37:/home/robert /mnt/home/robert nfs
```

### Sharing files with yourself using symbolic links
```sh
ln -s /nfs/home/ /home/username/Desktop/
```

A symbolic link points to a separate file system object. Reading, executing, or editing the symbolic link will read, execute, or edit the linked object. But if you move or delete the original the symbolic link, being nothing more than a pointer to a separate object, it will break.

A hard link, by contrast, is an exact duplicate of its target to the point that the two files will share a single inode. An inode is metadata describing an object’s attributes: in particular, its location within the file system.

```sh
nano file1
nano file2
ln file1 file1-hard
ln -s file2 file2-sym
ls -li
# 9569544 -rw-rw-r-- 2 ubuntu ubuntu 4 Sep 14 15:40 file1
# 9569544 -rw-rw-r-- 2 ubuntu ubuntu 4 Sep 14 15:40 file1-hard
# 9569545 -rw-rw-r-- 1 ubuntu ubuntu 4 Sep 14 15:40 file2
# 9569543 lrwxrwxrwx 1 ubuntu ubuntu 4 Sep 14 15:40 file2-sym -> file2

mv file1 newname1
mv file2 newname2

ls -il 
# file1, file1-hard is still there and, more important, still shares the same inode with newname1. Any edits to one file will be reflected in the other. file2-sym, sadly, has been orphaned.
```

## Troubleshooting system performance issues
### CPU load problems
1. Measuring CPU load 
- CPU load is a measure of the amount of work (meaning the number of currently active and queued processes) being performed by the CPU as a percentage of total capacity. Load averages that represent system activity over time, because they present a much more accurate picture of the state of your system, are a better way to represent this metric.
- CPU utilization (or usage) is a measure of the time a CPU is not idle (described as a proportion of the total CPU capacity).

```sh
uptime # get load of cpu
cat /proc/cpuinfo | grep processor # xem co bao nhieu core
```

2. Managing CPU load
```sh
top # show 
kill 1367
nice -15 /var/scripts/mybackup.sh
nice --15 /var/scripts/mybackup.sh # from -20 to 19. The higher the number, the nicer the process will be when it comes to giving up resources in favor of other processes.
renice 15 -p 2145 # use renice to change the way a process behaves even after it’s started.
```

Symbols for CPU-related metrics displayed by top
Metric|Meaning
------|-------
us|Time running high-priority (un-niced) processes
sy|Time running kernel processes
ni|Time running low-priority (nice) processes
id|Time spent idling
wa|Time waiting for I/O events to complete
hi|Time spent managing hardware interrupts
si|Time spent managing software interrupts
st|Time stolen from this VM by its hypervisor (host)

3. Making trouble (simulating CPU load)
```sh
yes > /dev/null & # gia lap de lam tang cpu
killall yes # kill by process name
```

### Memory problems
1. Assessing memory status
free parses the /proc/meminfo file and displays the total physical memory available and the way it’s currently being used. shared is memory that’s used by tmpfs to maintain the various pseudo file systems we’ve come to know and love, like /dev/ and /sys/. Buffers and cache are associated with memory used by the kernel for block level I/O operations.

```sh
free -h
```

2. Assessing swap status

```sh
vmstat 30 4 # return 4 readings with 30-second intervals between each reading
```

### Storage availability problems
```sh
df -h
```

1. Inode limits
```sh
df -i # show inode data
```

```sh
find . -xdev -type f | cut -d "/" -f 2 | sort | uniq -c | sort -n
```

Syntax|Function
------|--------
.|Start searching within and below the current directory.
-xdev|Remain within a single file system.
-type f|Search for objects of type file.
cut -d "/"|Remove text identified by the delimiter (/ character, in this case).
-f 2|Select the second field found.
sort|Sort lines of output, and send to standard out (stout).
uniq -c|Count the number of lines sent by sort.
sort -n|Display the output in numeric order.

2. The solution
```sh
dpkg --configure -a
apt-get autoremove
```

### Network load problems
1. Measuring bandwidth
```sh
iftop -i eth0
nethogs eth0
```

2. Shaping network traffic with tc
```sh
tc -s qdisc ls dev eth0 # list the tc rules
tc qdisc add dev eth0 root netem delay 100ms # add a rule that delays all traffic by 100 ms
tc qdisc del dev eth0 root # delete the rules
```

### Monitoring tools
1. Aggregating monitoring data
```sh
nmon
```
2. Visualizing your data
```sh
nmon -f -s 30 -c 120 # saves data collected every 30 seconds over a full hour (120 * 30 seconds) to a file in the current working directory.

wget http://sourceforge.net/projects/nmon/files/nmonchart31.tar
tar xvf nmonchart31.tar
./nmonchart ubuntu_170918_1620.nmon /var/www/html/datafile.html # convert the data files to the much more user-friendly .html format. In case you’re faced with an error complaining about the lack of a ksh interpreter, feel free to install the ksh package.
```

## Troubleshooting network issues
### Understanding TCP/IP addressing
1. What's NAT addressing?
The organizing principle behind NAT is brilliant: rather than assign a unique, networkreadable address to every one of your devices, why not have all of them share the single public address that’s used by your router? But how will traffic flow to and from your local devices? Through the use of private addresses. And if you want to divide network resources into multiple subgroups, how can everything be effectively managed? Through network segmentation.

2. Working with NAT addressing
The NAT protocol sets aside three IPv4 address ranges that can only be used for private addressing:
- 10.0.0.0 to 10.255.255.255
- 172.16.0.0 to 172.31.255.255
- 192.168.0.0 to 192.168.255.255

![[Pasted image 20230109164553.png]]

Following networking conventions, DHCP servers generally don’t assign the numbers 0, 1, and 255 to network devices.

![[Pasted image 20230109164743.png]]

**Subnet notation**
There are two commonly used standards: Classless Inter-Domain Routing (CIDR) notation
and netmask. Using CIDR, the first network in the previous example would be represented as 192.168.1.0/24. The /24 tells you that the first three octets (8×3=24) make up the network portion, leaving only the fourth octet for device addresses. The second subnet, in CIDR, would be described as 192.168.2.0/24.

These same two networks could also be described through a netmask of 255.255.255.0. That means all 8 bits of each of the first three octets are used by the network, but none of the fourth.

### Establishing nework connectivity
![[Pasted image 20230109172420.png]]

### Troubleshooting outbound connectivity
1. Tracking down the status of your network
```sh
lspci # list all the PCI-based hardware currently installed
lshw -class network # show only the subset of that profile that relates to networking
dmesg | grep -A 2 Ethernet
```
2. Asssigning IP address

**Defining a network route**
```sh
ip route
ip route add default via 192.168.1.1 dev eth0
```

**Requesting a dynamic address**
```sh
dhclient enp0s3
```

**Configuring a static address**
```sh
ip addr add 192.168.1.10/24 dev eth0
```

/etc/network/interfaces
```sh
auto enp0s3
iface enp0s3 inet static
address 192.168.1.10
netmask 255.255.255.0
gateway 192.168.1.1
```

```sh
systemctl restart networking
ip link set dev enp0s3 up
```

3. Configuring DNS service
**What's DNS?**
![[Pasted image 20230110135716.png]]

/etc/network/interfaces
```sh
dns-nameserver 8.8.8.8
dns-nameserver 8.8.4.4
```

4. Plumbing
```sh
traceroute google.com
```

### Troubleshooting inbound connectivity
1. Internal connection scanning: netstat
```sh
netstat -l | grep http
netstat -i # list network interfaces
```

2. External connection scanning: netcat
```sh
nc -z -v bootstrap-it.com 443 80
nmap -sT -p80 bootstrap-it.com
nmap -sT -p1-1023 bootstrap-it.com
```

## Troubleshooting peripheral devices
### Identifying attached devices 
```sh
lsblk # list block devices
lsusb # list usb devices
lspci # list pci devices
lshw -html > lshw-output.html
```

### Managing peripherals with Linux kernel modules
![[Pasted image 20230112111248.png]]

1. Finding kernel modules
```sh
ls /lib/modules
uname -r
ls /lib/modules/`uname -r`
ls /lib/modules/`uname -r`/kernel
lsmod # loaded modules
modprobe -c | wc -l # total modules
```

2. Manually loading kernel modules
```sh
find /lib/modules/$(uname -r) -type f -name ath9k*
modprobe ath9k # load module
lsmod | grep video
rmmod uvcvideo
modprobe uvcvideo
```

### Manually managing kernel parameters at boot time
1. Passing parameters at boot time
2. Passing parameters via the file system

A run level is a setting that defines the Linux system state for a particular session. Choosing between run levels 0–6 determines what services should be available, ranging from a full, graphic, multiuser system to no services at all (meaning, shut down).

/etc/default/grub
```sh
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash systemd.unit=runlevel3.target" # level 3 => multiuser, nographical mode
```

```sh
update-grub # update config for next boot time
```

### Managing printers
1. Basics of lp
```sh
lpq # list available printers
lpstat -p -d
lp -d Brother-DCP-7060D /home/user/myfile.pdf # print file
lp -H 11:30 -d Brother-DCP-7060D /home/user/myfile.pdf # The -H schedule setting always uses UTC time rather than local
```

2. Managing printers using CUPS

/etc/cups/cupsd.conf
```sh
#
# Configuration file for the CUPS scheduler.  See "man cupsd.conf" for a
# complete description of this file.
#

# Log general information in error_log - change "warn" to "debug"
# for troubleshooting...
LogLevel warn
PageLogFormat

# Deactivate CUPS' internal logrotating, as we provide a better one, especially
# LogLevel debug2 gets usable now
MaxLogSize 0

# Only listen for connections from the local machine.
Listen localhost:631
Listen /run/cups/cups.sock

# Show shared printers on the local network.
Browsing Off
BrowseLocalProtocols dnssd

# Default authentication type, when authentication is required...
DefaultAuthType Basic

# Web interface setting...
WebInterface Yes
```

```sh
systemctl status cups
systemctl stop cups
cat /etc/cups/printers.conf file
systemctl start cups
```

/etc/cups/printers.conf file
```sh
<Printer Canon_MF240@Canonc38c26.local>
UUID urn:uuid:53f0ea5e-ccc2-3b1b-61e9-9168d839a973
Info Canon_MF240@Canonc38c26.local
MakeModel CNMF240 Series, driverless, cups-filters 1.20.2
DeviceURI ipp://Canonc38c26.local:631/ipp/print
State Idle
StateTime 1624246536
ConfigTime 1624250314
Type 36948
Accepting Yes
Shared No
JobSheets none none
QuotaPeriod 0
PageLimit 0
KLimit 0
OpPolicy default
ErrorPolicy retry-job
</Printer>
<Printer HP-LaserJet-Pro-M404-M405>
UUID urn:uuid:663a75be-8b82-3c9f-4ce7-8b5d6d8a2a30
Info HP LaserJet Pro M404dw
MakeModel HP LaserJet Pro M402-M403n Postscript (recommended)
DeviceURI socket://192.168.1.250:9100
State Idle
StateTime 1667295971
ConfigTime 1649755573
Type 8425668
Accepting Yes
Shared Yes
JobSheets none none
QuotaPeriod 0
PageLimit 0
KLimit 0
OpPolicy default
ErrorPolicy retry-job
</Printer>
```

## DevOps tools: Deploying a scripted server environment  using Ansible

![[Pasted image 20230118101818.png]]

### What deployment orchestrators can do for you

Tool|Features
----|--------
Puppet|Broad community support<br>Some coding skills recommended<br>Extensible using Ruby<br>Requires agents installed on all clients
Chef|Integrated with Git<br>Some coding skills recommended<br>Extensible using Ruby<br>High learning curve<br>Broad community support<br>Requires chef-client installed on all clients
Ansible|Sysadmin friendly<br>Python-based<br>No code needed, no host-based agents<br>Simple, fast connections work via SSH<br>Run via text-based files (called playbooks)<br>Minimal learning curve
Salt|Works through agents (called minions)<br>Highly scalable<br>Sysadmin friendly

### Ansible: Installation and setup

```sh
apt install software-properties-common
apt update
apt install ansible
```

1. Setting up passwordless access to hosts
```sh
ssh-keygen
ssh-copy-id -i .ssh/id_rsa.pub ubuntu@10.0.3.142
```

2. Organizing Ansible hosts
/etc/ansible/hosts
```sh
[webservers]
192.168.1.31

[databases]
database1.mydomain.com
```

3. Testing connectivity
```sh
ansible webservers -m ping
ansible webservers -a "cp /etc/group /home/robert"
```

### Authentication
/etc/ansible/ansible.cfg
```sh
[privilege_escalation]
become=True
become_method=sudo
become_user=root
become_ask_pass=True
```

```sh
ansible --ask-become-pass webservers -m copy -a "remote_src=true src=/home/robert/group dest=/var/"
```

### Ansible playbooks
1. Writing a simple playbook
site.yml
```yml
---
- hosts: webservers
  tasks:
    - name: install the latest version of apache
      apt:
        name: apache2
        state: latest
        update_cache: yes
    - name: copy an index.html filte to the web root and rename it index2.html
      copy: src=/home/robert/project/index.html dest=/var/www/html/index2.html
      notify:
      - restart apache
    - name: ensure apache is running
      service: name=apache2 state=started
  handlers:
    - name: restart apache
      service: name=apache2 state=restarted
```

```sh
ansible-doc apt
ansible-playbook site.yml
```

2. Creating multi-tiered, role-powered playbooks
**Generating an Ansible Role**
```sh
mkdir roles
cd roles
ansible-glaxy init web-app
```

3. Managing passwords in Ansible
```sh
ansible-vault create mypasswordfile
ansible-playbook site.yml --ask-vault-pass
```
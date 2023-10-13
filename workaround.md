# What's this? WTF???
Файл в который я записывал все свои так называемые шпоргалки начиная с того момента когда я не знал что такое tcp handleshake, как посмотреть man и другие примитивы, по сему файл мягко говоря далек от идеала, и в нем можно найти как более менее структурированые записи так и вообще не понятные имеющие отношения пожалуй к конкретной задаче на конкретном месте работы. Сплю и вижу как я "причешу" этот файлы и он будет помогать не только мне, но нет )))   
 
 # Собеседования вопросы  
- как повысить приоритет процесса
- как посмотреть родителя и потомков процесса
- как посчитать топ вхождений в логе (ip адреса) python or bash
- что такое inode
- как посмотреть список блочных устройств
- как посмотреть утилизацию сетевых интерфейсов
- как спроксировать трафик (tcp or udp) 
## MacOS 
`00~` fix `printf '\e[?2004l'`
### install psql
brew install libpq
ln -s /usr/local/Cellar/libpq/10.3/bin/psql /usr/local/bin/psql
### tunnelblic dns timeout, dns cache clean
`sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`


# Linux || Unix
## Network
`nstat -az |grep UdpRcvbufErrors` - TSHOOT udp buffers
## Namespace
It's abstraction on OS's resources. Namespace has 7 types: Cgroups, IPC, Network, Mount, PID, User, UTS.
## Change default visual & editor
```
export VISUAL=nano
export EDITOR="$VISUAL"
```
### lsof  
* ожидает поключение
  `lsof -Pi | grep LISTEN`  

### Yum
- Yum download rpm with dependencies  
```
yum install yum-plugin-downloadonly
yum install --downloadonly --downloaddir=. <package-name>
```
Show alternative versions package  
`yum list --showduplicate nginx-module-vts.x86_64`  
Install version package  
`yum install nginx-module-vts-1.18.0-2.el7.ngx`  
# Файловые дескрипторы || file's descriptors
### кол-во открытых, не точное т.к. попадются строки одних и тех же файлов открытых другими процессами
lsof | wc -l 
### кол-во открыты, выделенные но не используемые, максимальное кол-во
cat /proc/sys/fs/file-nr

## Firewalld
`firewall-cmd --list-all`
### NFS on *nix for Windows 
https://docs.cloud.oracle.com/iaas/Content/File/Troubleshooting/troubleshootingWindowsNFS.htm


# Source Policy Routing
1. Create a table for iproute2
echo -e "200\tTableName" >> /etc/iproute2/rt_tables
2. Create a route
echo "default table TableName via 10.0.0.1" >> /etc/sysconfig/network-scripts/route-eth1
3. Create a rule
echo "from 10.0.0.2 table TableName" >> /etc/sysconfig/network-scripts/rule-eth1
4. Restart networking
/etc/init.d/network restart
************************************************************
yum provides *name.so* search library in repo
************************************************************
logrotate -d /etc/logrotate.conf
************************************************************
монтирование windows share smb с доменной авторизацией
only root
mount -t cifs //FILE-SRV-5/acquiring /tmp/test -o username=buh_mail,dom=invest,password=MySuperSecretPass
************************************************************

### Clear history command
`history -c			or			/home/username/.bach_history`  
## SELinux
temporarily disable: `echo 0 >/selinux/enforce` or `setenforce 0`
enable: `echo 1 >/selinux/enforce` or `setenforce 1`
Permanently disable:  
In Fedora Core and RedHat Enterprise, edit `/etc/selinux/config` SELINUX=enforcing change to SELINUX=disabled
**************************************************
******************TAR archive*********************
**************************************************
create archive:
tar -zcvf prog-1-jan-2005.tar.gz /home/jerry/prog
**************************************************
Extract files
tar -zxvf prog-1-jan-2005.tar.gz -C /tmp
**************************************************
tar with permissions
tar pzcvf tarball.tgz
tar pxvf tarball.tgz		untar need with permissions
Empty (clear) text type file:
cat /dev/null > /path/to/file.txt
**************************************************
Переименовать знаки вопроса
convmv -f koi8-r -t utf-8 -r *
convmv -f koi8-r -t utf-8 -r --notest *
**************************************************
####SNMP####
snmpwalk -v2c -c private-secret 192.168.31.1 -On
**************************************************


du -cks * | sort -rn |head -10			показывает и сортирует по размеру наиболее крупные директории (-h human_readeble) 
 
find /dir/name/where/delete -mtime +120 -exec rm \{\} \;		удаляет файлы старее 120 дней
find /dir/name/where/delete -type d -mtime +120 -exec rmdir -p {\} \;		удаляет старые файлы и папки.(старее 120 дней)
find $BACKUP_DIR -maxdepth 1 -type f -ctime +$DAYS_TO_RETAIN -delete

fetchmail -f <pathname> ---- for to define not default path configured file fetchmailrc

## Linux network debug & tuning
`sysctl -a`  
`netstat -s`  
`dmesg -T`  
```
net.netfilter.nf_conntrack_tcp_timeout_established=7200
net.core.somaxconn = 8192
net.ipv4.ip_local_port_range = 15000 65000
net.ipv4.tcp_syn_retries = 3
```
После изменения somaxconn нужно перезапустить приложение, что бы настройки применились на сокете приложения  

```
net.ipv4.ip_local_port_range = 1024 65535
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 15
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close = 5
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
```


***###Debian/Ubuntu###***
ubuntu version
cat /etc/issue *|or|*  lsb_release 
----
Disable daemon
# ls -l /etc/rc?.d/*apache2
lrwxrwxrwx 1 root root 17 2007-07-05 22:51 /etc/rc0.d/K91apache2 -> ../init.d/apache2
--//--
lrwxrwxrwx 1 root root 17 2007-07-05 22:51 /etc/rc6.d/K91apache2 -> ../init.d/apache2
# update-rc.d -f apache2 remove
## apt package manager
### Show all available versions of package_name
``apt-cache madison PACKAGE_NAME``  
### Add GPG key repo
``apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub``  
If your server behind proxy and apt-key was return time out (becase apt-key usign non http/https protocol, it use hpk://) use curl or wget, like this:  
``curl -sSL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub | apt-key add -``  



command for add user in Active Directory
dsadd user cn="Test Testov",ou=Samara,ou=Employees,dc=ccad,dc=synterra,dc=ru -disabled yes -mustchpwd yes -profile \\adcc.ccad.sytnerra.ru\profiles\$username$ -s adcc.ccad.synterra.ru -samid smr-tete01
dsquery user ou=samara,ou=employees,dc=ccad,dc=synterra,dc=ru -disabled -o rdn
dsquery user ou=samara,ou=employees,dc=ccad,dc=synterra,dc=ru -disabled | dsmod user -pwd Qwerty14
dsquery user ou=Tomsk,ou=Employees,dc=ccad,dc=synterra,dc=ru -disabled | dsmod user -disabled no
ввод компьюетра в домен:	netdom join

#linux to #Active Diretory #linux_ad
#install samba winbind samba-common
#configure /etc/samba/smb.conf 
""""""""""""""
workgroup = EXAMPLE
security = ads
realm = EXAMPLE.LOCAL
winbind uid = 10000-20000
winbind gid = 10000-20000
winbind use default domain = yes
winbind enum users = yes
winbind enum groups = yes
""""""""""""""
#join computer/server to domain
net ads join -U Administrator
#check wbind
wbinfo -t
#check authorithation
wbinfo -a EXAMPLE\\testuser%'password'


snom320
http://cc-web-3.ccad.synterra.ru/syncc-dev/test/snom320-6.5.20-SIP-j.bin #for update 6.*.*
http://cc-web-3.ccad.synterra.ru/syncc-dev/test/snom320-7.3.30-SIP-f.bin #for update 7.*.*
http://cc-web-3.ccad.synterra.ru/syncc-dev/test/snom320-7.3.30-SIP-bf.bin #for upgrade from 6.* to 7.*
http://cc-web-3.ccad.synterra.ru/syncc-dev/test/snom320-3.38-l.bin #for linux snom

runas /user:username@domain "command"


***Microsoft***
----------------
NetFramework 3.5 0x800F081F
Dism /online /enable-feature /featurename:NetFx3 /All /Source:E:\sources\sxs /LimitAccess
----------------
Windows Update
wuauclt /detectnow
----------------
msconfig - c:\WINDOWS\pchealth\helpctr\binaries\
----------------
RTC Debug (in register)
HKEY_CURRENT_USER\Software\Microsoft\Tracing\RTCDLL
EnableConsoleTracing - 1
EnableDebuggerTracing - 1
EnableFileTracing - 1
FileDirectory - where to write?
----------------
Windows 7
переменные среды environment
rundll32 sysdm.cpl,EditEnvironmentVariables
----------------
Source Based Routing
http://www.colobridge.net/wiki/%D1%81%D0%B5%D1%82%D0%B8/source_based_routing#конфигурационные_файлы

Postfix
***
lihgt deploy
http://wiki.centos.org/HowTos/postfix#head-c02f30bf0669d9b47a6c14c114243338b5ea1f27
***
catch all mail in one mailbox
http://www.cyberciti.biz/faq/howto-setup-postfix-catch-all-email-accounts/
***
postmap - игнорирование mx записи в DNS
***
telnet smtp 
ehlo gmail.com
mail from: hacker@gos.ru
rcpt to: sechenov@gos.ru
data
To: User Useroff
From: hacker@gos.ru
Subject: Top secret!!
Hello, 
This is an email sent by using the telnet command.
.
quit
***
Clear queue mail
mailq | grep MAILER-DAEMON | awk '{print $1}' | tr -d '*' | postsuper -d -
***


фильтр удаления из очереди
mailq | tail +2 | grep -v '^ *(' | awk  'BEGIN { RS = "" } { if ($8 == "email@address.com" && $9 == "") print $1 } ' | tr -d '*!' | postsuper -d -
***
Flush the queue: postqueue -f 

---
Ports firewall
25 smtp [mta] - incoming mail to postfix
80 http [mailbox] - web mail client
110 pop3 [mailbox]
143 imap [mailbox]
443 https [mailbox] - web mail client over ssl
465 smtps [mta] - incoming mail to postfix over ssl (Outlook only)
587 smtp [mta] - Mail submission over tls
993 imaps [mailbox] - imap over ssl
995 pops [mailbox] - pop over ssl
7071 https [mailbox] - admin console


**************************************************************
# SSL TLS Certificate
**************************************************************  
https://superuser.com/questions/1535116/generating-privatepublic-keypair-for-ssh-difference-between-ssh-keygen-and-ope  

### PEM (PKCS#1)
PEM – наиболее популярный формат среди сертификационных центров. PEM сертификаты могут иметь расширение .pem, .crt, .cer, и .key (файл приватного ключа). Она представляют собой ASCII файлы, закодированные по схеме Base64. Когда вы открываете файл pem формата в текстовом редакторе, вы можете увидеть, что текст кода в нем начинается с тега ``-----BEGIN RSA PRIVATE KEY-----`` и заканчивая тегом ``-----END CERTIFICATE-----``.  "PKCS#1" or "PEM" key format, which is Base64 encoding of an ASN.1 DER serialized structure. It's a basic ASN.1 sequence containing the RSA parameters (n, e, d, p, q, etc).  
Apache и другие подобные серверы используют сертификаты в PEM формате. Обратите внимание, что в одном файле может содержатся несколько SSL сертификатов и даже приватный ключ, один под другим. В таком случае каждый сертификат отделен от остальных ранее указанными тегами BEGIN и END. Как правило, для установки SSL сертификата на Apache, сертификаты и приватный ключ должны быть в разных файлах.  
___
View contents of PEM certificate file:  
`openssl x509 -in CERTIFICATE.pem -text -noout`  
___
PEM to DER:  
`openssl x509 -outform der -in CERTIFICATE.pem -out CERTIFICATE.der`  
____
PEM to PKCS#7:  
`openssl crl2pkcs7 -nocrl -certfile CERTIFICATE.pem -certfile MORE.pem -out CERTIFICATE.p7b`  
Where `MORE.pem` is file with chained intermediate and root certificates.  
___
### DER
DER формат – это бинарный тип сертификата вместо формата PEM. В PEM формате чаще всего используется расширение файла .cer, но иногда можно встретить и расширение файла .der. Поэтому чтобы отличить SSL сертификат в формате PEM от формата DER, следует открыть его в текстовом редакторе и найти теги начала и окончания сертификата (BEGIN/END). DER SSL сертификаты, как правило, используются на платформах Java.  
___
* View contents of DER-encoded certificate file:  
`openssl x509 -inform der -in CERTIFICATE.der -text -noout`  
___
* DER to PEM:  
`openssl x509 -inform der -in CERTIFICATE.der -out CERTIFICATE.pem`
___
### PKCS # 7 / P7B - is a container format for digital certificates.  
SSL сертификаты в формате PKCS # 7 или P7B — это файлы, которые хранятся в формате Base64 ASCII и имеют расширение файла .p7b или .p7c. P7B сертификаты содержат теги начала сертификата «—— BEGIN PKCS7 ——» и его конца «—— END PKCS7 ——«. Файлы в формате P7B включают в себя только ваш SSL сертификат и промежуточные SSL сертификаты. Приватный ключ при этом идет отдельным файлом. SSL сертификаты в формате PKCS # 7 / P7B поддерживают следующие платформы: Microsoft Windows и Java Tomcat.
### PFX СЕРТИФИКАТ (ФОРМАТ PKCS # 12)
Формат SSL сертификата PKCS # 12 или, как его еще называют, PFX сертификат — бинарный формат, при использовании которого в одном зашифрованном файле хранится не только ваш личный сертификат сервера и промежуточные сертификаты центра сертификации, но и ваш закрытый ключ. PFX файлы, как правило, имеют расширение .pfx или .p12. Обычно, файлы формата PFX используются на Windows серверах для импорта и экспорта файлов SSL сертификатов и вашего приватного ключа.
### КОНВЕРТАЦИЯ SSL СЕРТИФИКАТОВ В OPENSSL
Данные команды OpenSSL дают возможность преобразовать сертификаты и ключи в разные форматы. Для того чтобы сделать их совместимыми с определенными видами серверов, либо ПО. К примеру, Вам необходимо конвертировать обыкновенный файл PEM, который будет работать с Apache, в формат PFX (PKCS # 12) с целью применения его с Tomcat, либо IIS.


ssh-keygen -f pub1key.pub -i >> ~/.ssh/authorized_keys
### Convert PEM to DER
`openssl x509 -outform der -in certificate.pem -out certificate.der`
### Convert PEM to PFX
`openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt`
### Convert DER to PEM
`openssl x509 -inform der -in certificate.cer -out certificate.pem`
### Convert P7B to PEM
`openssl pkcs7 -print_certs -in certificate.p7b -out certificate.cer`
### Convert P7B to PFX
`openssl pkcs7 -print_certs -in certificate.p7b -out certificate.ceropenssl pkcs12 -export -in certificate.cer -inkey privateKey.key -out certificate.pfx -certfile CACert.cer`
### Convert PFX to PEM
`openssl pkcs12 -in certificate.pfx -out certificate.cer -nodes`
###
OpenSSL is expecting the RSA key to be in PKCS#1 format
`ssh-keygen -f key.pub -e -m pem`
### verify certificate:
`openssl s_client -showcerts -connect spdcvc.geolife.lan:636`  
### Generage cert
Generate key:  
`openssl genrsa -des3 -out private.key 2048`  
or  
`openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privatekey.key`  
remove pass|unecrypt key:  
`openssl rsa -in private.key -out public.key`  
Generate CSR:  
`openssl req -new -key private.key -out domain-name.csr`  
Generate crt:  
`openssl req -new -x509 -days 365 -nodes -out smtpd.cert -keyout smtpd.key`  
### Get certificate from server
`openssl s_client -showcerts -servername www.example.com -connect www.example.com:443 </dev/null`  
### Get fingerprint of certificate
`openssl s_client -connect www.example.com:443 < /dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout -in /dev/stdin`    



# MySQL
### Backup
`mysqldump -u [uname] -p[pass] [dbname] | gzip -9 > [backupfile.sql.gz]`  
`mysqldump -u $USER -p$PASSWORD --default-character-set=$CHARSET $DATABASE -c`  
### Restore
'mysql -u [uname] -p[pass] [db_to_restore] < [backupfile.sql]'  
* Create user and grant privileges
```
grant all privileges on wiki.* to 'wikiuser'@'localhost' identified by 'PASSWORD';
flush privileges;
set password for 'username'@'%' = password('SomeSecretPass');
```
* grant for admin user
`GRANT ALL PRIVILEGES ON *.* TO ‘peter’@’%’;`

#Soft#
MySQL Workbench
***
----------------------------------------------------------------------------------------------------------
mycli 
yum install python-pip python-devel
pip install mycli

# Python
## pip
install from private repo   
`pip install --no-cache-dir --index-url https://nexus3.somedomain.ru/repository/Pypi/simple/ poetry`
```
pip freeze > requirements. txt
```
### Alembic migrations
``alembic history -v``  
``alembic current``
### Install
yum instal python36 python36-devel python36-setuptools python-virtualenv
easy_install-3.6 pip

### On Windows, as an administrator:
```
> \Python27\python.exe Downloads\get-pip.py
> \Python27\python.exe -m pip install virtualenv

```
## FLASK
```
set FLASK_APP=microblog.py #windows
export FLASK_APP=microblog.py # linux
flask No module named (windows when FLASK_ENV=development)
python -m flask run
```
> Create a project folder and a venv folder within:
```
$ mkdir myproject
$ cd myproject
$ python3 -m venv venv
$ source env/bin/activate
```
> On Windows:
``py -3 -m venv venv``
> If you needed to install virtualenv because you are using Python 2, use the following command instead:
or
``python3 -m venv venv``  
``$ python2 -m virtualenv venv``
> On Windows:
```
 \Python27\Scripts\virtualenv.exe venv
```
> Before you work on your project, activate the corresponding environment:  
``$ . venv/bin/activate``  
On Windows:  
``> venv\Scripts\activate``  
Your shell prompt will change to show the name of the activated environment.
for activate virtual environment  
``cd <env_name> && source bin/activate``
  
---
## Luigi
> links  
https://github.com/spotify/luigi  
https://www.digitalocean.com/community/tutorials/how-to-build-a-data-processing-pipeline-using-luigi-in-python-on-ubuntu-20-04






----------------------------------------------------------------------------------------------------------
# Genesys
Administrator, чтобы работало нужно в анексах добавить секцию security и в ней параметр Administrator=1

***************************
****Tools Soft Software****
***************************
programm
----------------
"Extreme GPU Bruteforcer"	password recovery
----------------
pwgen - password generator
----------------
Session ShortCuts SSS (табы, tab, tabs, вкладки, putty, kitty)
----------------
tcl http://equi4.com/tclkit/download.html
----------------
inotify - monitoring file system events (linux)
----------------
Hamster - mail server
----------------
Console2 - console alternate cmd
----------------
ProcessExplorer
----------------
ProcessMonitor
----------------
pstools
----------------
TcpView
----------------
snmpb
----------------
CamStudio - video recorder from desktop
----------------
TFTPD32 - dhcp, tfpt, ftp

# Monitoring
----------------
monit - alternate nagios  
munin - alternate cacti  
## Disk and IO utilization
`iostat`  
`iotop`  
`dstat`  
`atop`  
`ioping`
## Network Linux utilization
`sar -n DEV 1 3`  
`nload`  
`iftop`  
## Prometheus
### Docks
#### Expression language data type
* Instant vector - a set of time series containing a single sample for each time series, all sharing the same timestamp
* Range vector - a set of time series containing a range of data points over time for each time series
* Scalar - a simple numeric floating point value
* String - a simple string value; currently unused
#### Aggregation operators
can be used to aggregate the elements of a single instant vector, resulting in a new vector of fewer elements with aggregated values  
Examples:
`increase(starlette_responses_total{app="$app", kubernetes_namespace="p-layer",status_code!="4.*|5.*"}[5m])` - many vectors (many graphes)
`sum(increase(starlette_responses_total{app="$app", kubernetes_namespace="p-layer",status_code!="4.*|5.*"}[5m]))` - single vector

### Get top time series metrics
`topk(20, count by (__name__, job)({__name__=~".+"}))`  
## Check config validation
`promtool check config prometheus.yml`  
----------------

Roundcube
"Настройки" - Вкладка "Профили" - в требуемом профиле поле E-Mail - поменять домен с cc-mail-2.ccad.synterra.ru на cc.synterra.ru

Mailbox
/home/vmail/mail - пользовательские mailbox

#Входящие/исходящие письма на примере test5@cc.synterra.ru
/home/vmail/mail/test5@cc.synterra.ru/cur/
/home/vmail/mail/test5@cc.synterra.ru/.Sent/cur/


************************************************************************************
Intel DH67BL c интегрированной сетевухой Intel(R) 82579V Gigabit Network Connection драйвер качать по ссылке
http://catalog.update.microsoft.com/v7/site/ScopedViewRedirect.aspx?updateid=4974078d-923c-4c00-9b64-5b6c88beb5d4
В файл e1c62x64.inf добавить две строки
[Intel.NTamd64.6.1] 
; DisplayName                   Section        DeviceID 
; -----------                   -------        -------- 
%E1502NC.DeviceDesc%            = E1502,       PCI\VEN_8086&DEV_1502 
%E1502NC.DeviceDesc%            = E1502,       PCI\VEN_8086&DEV_1502&SUBSYS_00011179 
%E1503NC.DeviceDesc%            = E1503,       PCI\VEN_8086&DEV_1503 
%E1503NC.DeviceDesc%            = E1503,       PCI\VEN_8086&DEV_1503&SUBSYS_00011179 

установить драйвера с помощью pnputil -i -a path\e1c62x64.inf
************************************************************************************

*** asterisk ***
*IP to Extention*
asteris -r
database show
********************
*** MTT SIP ***
//конфигурация для одного IP на несколькил лицевых счетах
;SIP Trunk
[mtt-main]
type=friend
defaultexpiry=120
host=login.mtt.ru
;
;### По рекомендации тех.поддержки МТТ
;### Для обеспечения подстановки номера А.
;defaultuser=883140776330430
;fromuser=883140776330430
username=883140776330430
;
secret=!m{uf2cHj
context=mtt
dtmfmode=rfc2833
disallow=all
allow=alaw,ulaw
insecure=invite,port
;nat=force_rport,comedia




kannel sms sendsms
http://sms-gate.site.lan:13003/cgi-bin/sendsms?username=Beeline&password=passlink&from=88002002545&to=79057906987&charset=UTF-8&coding=2&text=%D0%A2%D0%B8%D0%B1%D0%B5+%D0%BF%D0%B8%D1%81%D0%B4%D0%B5%D1%86!!!

http://kannel-nss.site.ru:13013/cgi-bin/sendsms?username=panaceamobile&password=passlink&from=88002002545&to=79057906987&charset=UTF-8&coding=2&text=%D0%A2%D0%B8%D0%B1%D0%B5+%D0%BF%D0%B8%D1%81%D0%B4%D0%B5%D1%86!!!


***********
***Cisco***
***********

***FWSM***
#
# Context я всегда юзал single
#!!! Be attention, need reboot!!!
conf t 
mode single
#
#
session slot 8 processor 1
#
https://www.ciscopress.com/articles/article.asp?p=1722547&seqNum=3
#

##First conf for time##
clock timezone MSK 3 0
service timestamps log datetime year localtime msec
service timestamps debug datetime year localtime msec
ntp source GigabitEthernet0/0
ntp master 3
ntp update-calendar
ntp server 89.169.173.117
ntp server 95.128.246.34
ntp server 193.106.92.60
***********
Cisco aux to console
show line
look vty number (X) of aux port
-*** configure aux line:
 line aux 0
  speed 9600
  databits 8
  parity none
  stopbits 1
  exec-timeout 0 0
  no activation-character
  no editing
  transport input telnet
  transport output none
  escape-character NONE
!****
2000+X = telnet port
telnet IP_current_aux_router 2000+X
for disconnect press Ctrl+6 and x then command disconnect
********************************************
********************************************
service unsupported-transceiver
no errdisable detect cause gbic-invalid
errdisable recovery cause gbic-invalid
********************************************
********************************************
**SFP sfp 3thd party non cisco**
service unsupported-transceiver
no errdisable detect cause gbic-invalid
errdisable recovery cause gbic-invalid
********************************************
********************************************
*IPSEC module*
show crypto engine accelerator statistic slot 7
show crypto engine brief 
show crypto eli
***********
like show module on 2900 (or ISR G2)
show inventory
***********
event manager applet VLAN_ADD
 event cli pattern "^switchport trunk allowed vlan [0-9].*" sync yes
 action 1.0 puts "!"
 action 2.0 puts "! LOSHARA DOBAV' add"
 action 4.0 puts nonewline "!"
 action 5.0 set _exit_status "0"
 action 6.0 exit
***********
event manager applet nat-sess-count
 event timer watchdog time 600 maxrun 60
 action 010 cli command "enable"
 action 030 cli command "configure terminal"
 action 040 cli command "do-exec show ip nat translations total"
 action 090 regexp "^.+\s([0-9]+)" "$_cli_result" match total_translations
 action 100 cli command "snmp mib expression owner nat name 1"
 action 110 if $_regexp_result eq "1"
 action 120  cli command "expression $total_translations"
 action 130 else
 action 140  cli command "expression 0"
 action 150  cli command "exit"
 action 160 end
***********
 *LACP port-channel Etherchannel*
 show lacp neighbor
 show inter port-channel 1 etherchannel
 show etherchannel summury
***********
***Cisco ASA***
показать пароль или ключи pre shared key
more system:running-config | in key
*traffic *
show interfaces | incl line|\/sec
***
output redirect
show ip nat translations | redirect ftp://username:password@hostname.example.lan/nat.txt
***
ACLs
*dynamic VPN IPSEC where 195.19.88.9 vpn host
    permit esp any host 195.19.88.9
    permit udp any host 195.19.88.9 eq isakmp					(port 500)
    permit udp any host 195.19.88.9 eq non500-isakmp			(port 4500)
    permit udp any host 195.19.88.9 eq 10000
***
http://netconfigure.net/index.php/en/forum-en/5-ip-/155---cisco-isr--siph323-gateway-isp-trunk-cme---sipsccp
***	
! включаем архивирование всех изменений конфига, скрывая пароли в логах
archive
 log config
  logging enable
  hidekeys
! историю изменения конфига можно посмотреть командой
show archive log config all
***
! включаем на интерфейсе подсчет пакетов передаваемых клиентам — удобно просматривать кто съедает трафик
ip accounting output-packets
! посмотреть статистику можно командой
show ip accounting
! очистить
clear ip accounting
**************************************************************************************************************
airnet standalone to lightwaght AP
archive download-sw/overwrite/force-reload tftp://<IP address of the  TFTP server>//<image>
**************************************************************************************************************
***first configure cisco***
no ip domain-lookup
ip domain-name mydomain.com
service timestamps debug datetime msec localtime year
service timestamps log datetime msec localtime year
service password-encryption
logging on
logging buffered informational
logging buffered 320000
username SuperUser secret SuperPassword
enable secret SuperPuperPassword123!
vtp mode transparent
vtp domain MyDomain
vtp version 3
vtp password VTPsecurityPass
spanning-tree mode rapid-pvst
spanning-tree logging
spanning-tree portfast default
spanning-tree portfast bpduguard default
no ip http server
no ip http secure-server
crypto key generate rsa
login delay 2
login block-for 240 attempts 3 within 60
!sh login failures
line vty 0 4
transport input telnet ssh
logging synchronous
exec-timeout 60 0
end
ip ssh port 3333 rotary 1
line vty 5 15 
rotary 1
transport input ssh
logging synchronous
exec-timeout 60 0
end
write
**********************
WEBVPN install
webvpn install svc flash0:/anyconnect-macosx-i386-3.1.12020-k9.pkg sequence 5
**********************
crypto pki trustpoint
Кошка требует pkcs12 формат, для этого cert нужно преобразовать в pem него и key сварить p12
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt
//openssl x509 -in developer_identity.cer -inform DER -out developer_identity.pem -outform PEM
//openssl pkcs12 -export -inkey mykey.key -in developer_identity.pem -out iphone_dev.p12

crypto pki import VPN2020 pkcs12 tftp: password SomeSuperPassword
% Importing pkcs12...
Address or name of remote host []? 10.1.0.13
Source filename [VPN2020]? vpn.pfx
Reading file from tftp://10.1.0.13/vpn.pfx
Loading vpn.pfx from 10.1.0.13 (via Tunnel10): !
[OK - 7125 bytes]

**********************
VPN Cisco
*States in Main Mode Exchange*
State			Explanation
MM_NO_STATE		The ISAKMP SA has been created, but nothing else has happened yet. It is "larval" at this stage—there is no state.
MM_SA_SETUP		The peers have agreed on parameters for the ISAKMP SA.
MM_KEY_EXCH		The peers have exchanged Diffie-Hellman public keys and have generated a shared secret. The ISAKMP SA remains unauthenticated.
MM_KEY_AUTH		The ISAKMP SA has been authenticated. If the router initiated this exchange, this state transitions immediately to QM_IDLE, and a Quick Mode exchange begins.
*States in Aggressive Mode Exchange*
State			Explanation
AG_NO_STATE>	The ISAKMP SA has been created, but nothing else has happened yet. It is "larval" at this stage—there is no state.
AG_INIT_EXCH	The peers have done the first exchange in aggressive mode, but the SA is not authenticated.
AG_AUTH			The ISAKMP SA has been authenticated. If the router initiated this exchange, this state transitions immediately to QM_IDLE, and a quick mode exchange begins.
*States in Quick Mode Exchange*
State	 		Explanation
QM_IDLE			The ISAKMP SA is idle. It remains authenticated with its peer and may be used for subsequent quick mode exchanges. It is in a quiescent state.
*show crypto isakmp sa Field Descriptions*
Field			Description
f_vrf/i_vrf		The front door virtual routing and forwarding (FVRF) and the inside VRF (IVRF) of the IKE SA. If the FVRF is global, the output shows f_vrf as an empty field.
*********************
ACL inbound in
IPv4 Example

!--- Anti-spoofing entries are shown here.
!--- Deny special-use address sources.
!--- Refer to RFC 3330 for additional special use addresses.
access-list 110 deny ip host 0.0.0.0 any
access-list 110 deny ip 127.0.0.0 0.255.255.255 any
access-list 110 deny ip 192.0.2.0 0.0.0.255 any
access-list 110 deny ip 224.0.0.0 31.255.255.255 any
!--- Filter RFC 1918 space.
access-list 110 deny ip 10.0.0.0 0.255.255.255 any
access-list 110 deny ip 172.16.0.0 0.15.255.255 any
access-list 110 deny ip 192.168.0.0 0.0.255.255 any
!--- Deny your space as source from entering your AS.
!--- Deploy only at the AS edge.
access-list 110 deny ip YOUR_CIDR_BLOCK any
!--- Permit BGP.
access-list 110 permit tcp host bgp_peer host router_ip eq bgp 
access-list 110 permit tcp host bgp_peer eq bgp host router_ip
!--- Deny access to internal infrastructure addresses.
access-list 110 deny ip any INTERNAL_INFRASTRUCTURE_ADDRESSES
!--- Permit transit traffic.
access-list 110 permit ip any any
IPv6 Example
The IPv6 access-list must be applied as an extended, named access-list.
!--- Configure the access-list.
ipv6 access-list iacl
!--- Deny your space as source from entering your AS.
!--- Deploy only at the AS edge.
 deny ipv6 YOUR_CIDR_BLOCK_IPV6 any
!--- Permit multiprotocol BGP.
 permit tcp host bgp_peer_ipv6 host router_ipv6 eq bgp
 permit tcp host bgp_peer_ipv6 eq bgp host router_ipv6
!--- Deny access to internal infrastructure addresses.
deny ipv6 any INTERNAL_INFRASTRUCTURE_ADDRESSES_IPV6
!--- Permit transit traffic.
 permit ipv6 any any
!--- Permit DHCP
permit tcp any any eq 67
permit tcp any any eq 68
permit udp any any eq bootps
permit udp any any eq bootpc

***
***
#service-module gigabitEthernet 2/0 session
CTRL-SHIFT-6-X
#disconnect
***
!#privileges startup-config: ->
username consultant privilege 10 secret 7JEGXfnR
enable secret level 10 8PDe4j6c
privilege exec all level 10 show
privilege exec level 10 show startup-config
file privilege 10
******************
in new IOS 15.5 and early
service internal
service unsupported-transceiver
******************
***PPTP client on cisco IOS***
service internal <- Unlocks some 'hidden' IOS features required to inititate a PPTP connection
!
vpdn enable
!
vpdn-group PPTP
 request-dialin
 protocol pptp
 rotary-group 0
 initiate-to <ip address of remote PPTP server>
!
interface Dialer1
 description PPTP client interface
 mtu 1400
 ip address negotiated
 ip nat outside
 ip virtual-reassembly
 encapsulation ppp
 ip tcp adjust-mss 1360
 dialer in-band
 dialer idle-timeout 60
 dialer string 1 <- Required but not used, PPTP connection wont initiate without this line.
 dialer vpdn
 dialer-group 1
 no peer neighbor-route <- Resolve recursive routing problems that can happen.
 no cdp enable <- Don't need CDP running.
 ppp encrypt mppe auto
 ppp authentication ms-chap-v2 callin
 ppp chap hostname <username>
 ppp chap password <password>
 ppp eap refuse <- Required connecting to Win 2k8 as it negotiates differently to 2k3.
 ppp chap refuse <- As above.
 ppp ms-chap refuse <- As above.
 !
ip route X.X.X.X Y.Y.Y.Y Dialer1 <- Route the remote subnets out your dialer interface.
!
ip nat inside source route-map RM-PPTP interface Dialer1 overload
!
access-list 100 permit X.X.X.X Y.Y.Y.Y any <- Internal subnet to match the NAT route-maps.
!
dialer-list 1 protocol ip permit <- Match any traffic to remote subnets to trigger PPTP dialer.
!
route-map RM-PPTP permit 10
 match ip address 100
 match interface Dialer1
***
license boot module c2900 technology-package uck9
license boot module c2900 technology-package data9
***
cisco Compact Flash original fdisk 512mb | sectors =>
Device	Boot	Start	End		Blocks	Id	System
/dev/sdb1	*		63	1000792	500365	4	FAT16 <32M
***
#aux for access to console "telnet local_IP_address PORT (where PORT=2000+line_number)"
conf t
 line aux 0
  speed 9600
  databits 8
  parity none
  stopbits 1
  exec-timeout 0 0
  no activation-character
  no editing
  transport input telnet
  transport output none
  escape-character NONE


ISP link
no cdp enable
no mop enable
spanning-tree bpdufilter enable


	
HP MFU Server
http://doc.elcat.kg/Misc/SOMag/content/2008/samag_12_73/samag12(73)-44-48.pdf
http://forum.ru-board.com/topic.cgi?forum=8&topic=24095&start=40#10


***********
****SSH****
***********
root access via ssh
in config file /etc/ssh/sshd_config set "PermitRootLogin" to "no"
---
ssh-keygen -t rsa -b 4096 -C "your@email.com"
# ssh-copy-id -i /root/.ssh/id_rsa.pub user@hostOrIp
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
user@hostOrIp's password:
Number of key(s) added: 1

#Now try logging into the machine, with:   "ssh 'user@hostOrIp'"
#and check to make sure that only the key(s) you wanted were added.
---
#### SOCKS proxy  
emulation in SSH client  
`ssh -D 5555 user@remotehost -f -N` где -D 5555 - эмуляция SOCKS сервера через порт 5555  
-f  - работа в фоне, после аутентификации  
-N - не запускать shell на удаленном хосте.  
## SSH Tunneling
https://www.ssh.com/academy/ssh/tunneling/example  
#### Local Forwardig 
`ssh -L 80:intra.example.com:80 gw.example.com` - curl http://localhost:80 - will return answer from intra.example.com:80 

***********
multiline commands over ssh
ssh root@${mod_ib_01} "(
	cd ${deploy_path}
	./stop-mod-ib.sh module-ib-tst253.yml
    ./start-mod-ib.sh Qwerty14 module-ib-tst253.yml
)"




prod-nix1
http://stackoverflow.com/questions/4358343/why-cant-get-this-page-in-linux-with-wget-telnet
http://lwn.net/Articles/92727/
http://www.faqs.org/rfcs/rfc1323.html


**********************
********Zimbra********
**********************
how to view mailbox size: zmmailbox -z -m accountname gms
how to delete mailbox folder: zmmailbox -z -m accountname emptyFolder /Inbox
how to view folder details: zmmailbox -z -m accountname gaf -v
*
restart mailbox
zmmailboxdctl restart
*
grant briefcase all users портфель все пользователям
zmprov -l gaa| while read USER; do zmmailbox -z -m $USER cm --view contact -F# "/Адресная книга предприятия" zimbra@geolife.ru /_geolife.lan ;  done
zmmailbox -z -m info@mydoamin.com mfg /Inbox account target.user@mydomain.com rwixda
//zmmailbox -z -m suhov@geolife.ru mfg /Briefcase/Инструкции account babkina@geolife.ru r
zmprov -l gaa| while read USER; do echo $USER; zmmailbox -z -m $USER cm --view briefcase -F# "/Инструкции" suhov@geolife.ru /Briefcase/Инструкции ;  done
zmprov -l gaa| while read USER; do echo $USER; zmmailbox -z -m $USER cm --view briefcase -F# "/Briefcase/Формы договоров" zmbriefcases@geolife.ru "/Формы договоров" ;  done
zmprov -l gaa| while read USER; do echo $USER; zmmailbox -z -m $USER cm --view briefcase -F# "/Briefcase/Реквизиты" zmbriefcases@geolife.ru "/Реквизиты" ;  done
********
zmmailbox -z -m maximova@ech.ru cm --view contact -F# "/Адресная книга предприятия" zimbra@geolife.ru /_geolife.lan
zmmailbox -z -m maximova@ech.ru cm --view briefcase -F# "/Инструкции" suhov@geolife.ru /Briefcase/Инструкции
zmmailbox -z -m maximova@ech.ru cm --view briefcase -F# "/Briefcase/Формы договоров" zmbriefcases@geolife.ru "/Формы договоров"
zmmailbox -z -m maximova@ech.ru cm --view briefcase -F# "/Briefcase/Реквизиты" zmbriefcases@geolife.ru "/Реквизиты"
*********
подключить целый ящик mailbox другому пользователю
zmmailbox -z -m share@domain.com mfg / account user@domain.com rwixd
zmmailbox -z -m user@domain.com cm /shared share@domain.com /
*********





VMware
CentOS
echo "- - -" > /sys/class/scsi_host/host#/scan

vmware tools
yum install vmware-tools-esx-nox
vim /etc/vmware-tools/tools.conf disable-tools-version=false (was true)
/etc/vmware-tools/init/vmware-tools-services restart

check HW compatability


CHECK LIST
###Deploy new server on linux
1. Create personal user with password.
2. Forbid root access over ssh.
3. Register in Spacewalk
4. Import key http://spacewalk.geolife.lan/pub/rpm-import
5. Install "VMware Tools" (if it VM).
6. Upgrade server.

Spacewalk
1. https://fedorahosted.org/spacewalk/wiki/RegisteringClients
2. then import keys http://spacewalk.geolife.lan/pub/rpm-import

Bacula
$ dir
drwxrwxrwx   1 root     root               0  2010-11-23 13:58:28  F:\design\art-director/
d-wx-wx-wx   1 root     root               0  2012-11-21 12:25:12  F:\design\designer/
$ cd F:\\design\\designer
cwd is: F:\design\designer/


Бизнес процессы
Alfresco задачи, цели


# Performance web monitoring
TTFB = RTT +    

# NGINX #
`nginx -V 2>&1 | grep --with-http_mp4_module` - grep modules  
https://www.nginx.com/blog/regular-expression-tester-nginx/  
self signed самоподписанный сертификат  
``sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt``
общий вид location:
```
location <modifier> <prefix> {
...
}
```
### Modules 
```
make modules
mkdir /nginx_module/
cp objs/ngx_http_vhost_traffic_status_module.so /nginx_module/
```
разнести по балансерам в /etc/nginx/modules
`chown root. ngx_http_vhost_traffic_status_module.so`  
For more look at this https://sysadmin.pm/nginx-build-module-sh/ and here https://habr.com/ru/company/tinkoff/blog/452336/
## HTTPS TLS
https://ssl-config.mozilla.org/  
https://gist.github.com/paskal/628882bee1948ef126dd  
### return body
```
location / {
    return 200 'gangnam style!';
    # because default content-type is application/octet-stream,
    # browser will offer to "save the file"...
    # if you want to see reply in browser, uncomment next line 
    # default_type application/json;
    # or text/plain
```
### if file exist maintanance
```
location / {
try_files $uri $uri/index.html $uri.html @backend;
}
location @backend {
if (-f /system/maintenance.html) {
return 503;
break;
}
proxy_pass http://backend;
}
error_page 503 /system/maintenance.html;
location = /system/maintenance.html {
root /srv/www/maint;
}
```
### locations proxy-pass
- если proxy-pass без URI то location передается как есть на proxy-pass  
- если proxy-pass c URI, то нормализованны URI из location меняется на URI из proxy-pass 
подробнее тут https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass  
- location могут быть вложенными, за некоторыми исключениями:
- Location с модификатором = не может иметь вложенных location;
- Location с модификаторами ~ и ~* внутри себя может содержать только location с теми же модификаторами.
- by default location works like prefix, example bellow will match sitename.com/testing and sitename.com/test/123/ and etc.
location /test  
- location for exact match bellow  
locatin = /test  
- case-sensitive regexp location  
locatioin ~ /test[0-9]  
- case insensitive regexp location  
locatin *~ /test[0-9]  
- prefered match then regexp  
location ^~ /test  
### matching order
1. = exact  
2. ^~ prefered longest prefix mattch regexp  
3. ~ и ~* regexp. ~ регистрозависимый, ~* регистронезависимый  
4. / prefix (longest prefix match)  
location ~*\.php$ - знак $ означает конец строки
## Nginx stippets
#### Deny all attempts to access hidden files such as .htaccess or .htpasswd
```
location ~ /\. {
    deny all;
}
```


### rewrite_mod
### flags: 
redirect = 302 (temporarily redirect)
permanent = 301 (permanent redirect)
last = обозначает последнее правило, далее только поиск location
break = (into location) продолжаем выполнение в текущем location
 = (нет флага) продолжает обработку в текущем location

### GZIP
gzip on;
gzip_types /plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript font/woff2;
#redirect return
location /swagger {
  return 302 /swagger/;
}
location /swagger/ {
    proxy_pass http://192.168.109.253:9002/;  # note the trailing slash here, it matters!
}

### Order processing.
```
typedef enum {
     NGX_HTTP_POST_READ_PHASE = 0,
     NGX_HTTP_SERVER_REWRITE_PHASE,
     NGX_HTTP_FIND_CONFIG_PHASE,
     NGX_HTTP_REWRITE_PHASE,
     NGX_HTTP_POST_REWRITE_PHASE,
     NGX_HTTP_PREACCESS_PHASE,
     NGX_HTTP_ACCESS_PHASE,
     NGX_HTTP_POST_ACCESS_PHASE,
     NGX_HTTP_TRY_FILES_PHASE,
     NGX_HTTP_CONTENT_PHASE,
     NGX_HTTP_LOG_PHASE
} ngx_http_phases;
```

# wi-fi wifi
### unifi ap pro
ubnt/ubnt - default password  
syswrapper.sh upgrade http://10.10.3.11:8080/dl/firmware/U7P/2.3.9.1693/firmware.bin

### Cisco ME (Mobility Express)
чтобы сделать даунгрейд точке являюшейся контроллером, нужно через консольный кабель поключиться к точке (apciscoshell) и выполнить следующие команды:
ap
#archive download-sw /reload tftp://<tftp server ip address>/<filename.tar>

# svn server***
run server /usr/bin/svnserve_other -d --listen-port=3691 --listen-host=svnother.geolife.ru -r /svn/repo/testsvn/
svnadmin create /svn/repo/testsvn/front1_nginx
# svn client***
copy all directories and configuration files to svn's local working directory 
#svn co svn://svnother.geolife.ru:3691/testrepo ./svn_test/
#svn add --force *
#svn commit -m 'update
#rm -rf

---
### Avaya
``incomint pstn number  ``
display inc-call-handling-trmt trunk-group 1 
#
# transit calls like EC500
change tandem-calling-party-num
                         CALLING PARTY NUMBER CONVERSION 
                                 FOR TANDEM CALLS
                      Incoming Outgoing                            Outgoing
      CPN             Number   Trunk                               Number
 Len  Prefix          Format   Group(s)    Delete  Insert          Format
     (who calling)
 10   4                         11         all     4959742525       pub-unk 
 10   9                         11         all     4959742525       pub-unk 
                                                                            
#
list ip-interface all 
*****
announcement
In some applications, assigning the format (for example, CCITTμ-Law) sets the
remainder of the default parameters. Check each parameter carefully, and
change the default setting to match the required parameters if necessary. Note
that CCITT μ-Law or A-Law can be referred to as ITU G.711 μ-Law or ITU G.711
A-Law
*****

# снятие блокировки data locked
status login
reset login-id NUM_SESSION

#ring all
terminated-extension-group or calling answer group=Coverage-Answer-Group
terminated-extension-group - if someone busy call not archive this extension (will BUSY sygnal)

Avaya Glance DHCP
HTTPSRVR=10.1.13.10,HTTPPORT=81,MCIPADD=10.1.13.10,TPSLIST=10.1.14.15:80,PUSHCAP=2222,PUSHPORT=80
*****
маршрутизация одного номера на другую станцию
change aar analysis 0
change uniform-dialplan 0
*****
cms supervisor
terminal cvsup
****
подставлять номер АОН
change public-unknown-numbering 0
****
перезагрузка чего-либо
busyout somethin
release somethin
****
IP DECT
WEB - DECT - System - Subscriptions = With System AC 
					- Authentication Code = any number code (example 20170913)
On phone register with AC 20170913, WEB - User - Anonymous - apear new row
WEB - User - new IPEI empty AC any code
On phone call *0*1176*1234# where 0 = ID Master, 1176 - number and 1234 - AC for user
****
#CDR
you need cdr data collector (any)
https://blog.upinget.com/2012/08/07/avaya-cdr-capturing-tool/
https://sourceforge.net/projects/avayacdr/
you need clan
you need ip for endpoint with collection software
change node-name (map name of cdr_endpoint to ip address)
change ip-services (map clan to cdr_endpoint and ip port) CDR1
change system cdr (cdr properties that you want)
****
Avaya SBCE
traceSBC

****
circ - следующий свободный агент в последовательности.
UCD-MIA - свободный агент, который не был задействован дольше всех с момента последнего вызова.
UCD-LOA - свободный агент, имеющий наименьший показатель процентного содержания рабочего времени с момента входа в систему.
EAD-MIA- свободный агент с наивысшей квалификацией, который не был задействован дольше всех с момента последнего вызова.
EAD-LOA- свободный агент, имеющий наивысшую квалификацию и наименьший показатель процентного содержания рабочего времени с момента входа в систему.
DDC- первый агент, администрированный в этой группе поиска. В случае занятости первого агента вызов поступает ко второму агенту, и так далее.
pad -- Enter pad (percent allocation distribution) to select an agent from a group
of available agents based on a comparison of the agent's work time in the
skill and the agent's target allocation for the skill.
slm Enter slm when you want to:
1. Compare the current service level for each SLM-administered skill
to a user-defined call service level target and identify the skills that
are most in need of agent resources to meet their target service
level.
2. Identify available agents and assess their overall opportunity cost,
and select only those agents whose other skills have the least
need for their service at the current time.
****




****
display system-parameters customer-options 
****
on ssh
swversion
    Operating system:  Linux 2.6.18-128.AV07smp i686 i686
                Built:  Aug 19 05:12 2009
             Contains:  02.1.016.4
        CM Reports as:  R015x.02.1.016.4
    CM Release String:  S8400-015-02.1.016.4
*****
station type for one-x 9630 of 4620
*****
1. Разграничения в пределах станции - с помощью COR (какому на какой можно звонить, какому нет - на страницах Calling Permission в ch cor) 
2. Ограничения по дальности (город/межгород/международка) - при помощи FRL, проверяется в route при выходе на транк. 8 вариантов от 0 до 7. 
3. Разграничения про маршрутам (кому через какой выход идти) - при помощи PGN. По умолчанию PGN = Time of Day chart (change cor). 8 вариантов от 1 до 8. 
*****
phone factory reset
Avaya 1600 sets: (1608 or 1616)

1)	Press the MUTE button.
2)	Type in Logoff using the keypad followed by the pound sign (564633#)
3)	At the prompt press appropriate key 	*=no 	# = yes
4)	If yes, system indicates “Logging off”
5)	Ext. = xxxx   Enter ext # you want the phone to be changed to followed by the # sign 
(to keep existing ext without changing to new extension #, press #= ok)  
6)	Enter Password at prompt – password for all phones is “123456” followed by # sign.

Avaya 4600 sets: (4608 or 4616)
1)	Press the HOLD button.
2)	Type in Logoff using the keypad followed by the pound sign (564633#)
3)	At the prompt press appropriate key 	*=no 	# = yes
4)	If yes, system indicates “Logging off”
5)	Ext. = xxxx   Enter ext # you want the phone to be changed to followed by the # sign 
(to keep existing ext without changing to new extension #, press #= ok)  
6)	Enter Password at prompt – password for all phones is “123456” followed by # sign.

9600 Series Phones
1.While the phone is on-hook and idle, press the following sequence: MUTE 2 7 2 3 8 # (MUTE C R A F T #).
2.Scroll the menu and select Clear.
3.Press Clear again to confirm the action. The phone settings are cleared and the phone restarts.





##################################################################################################
CheckPoint
https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk53980
##################################################################################################
***Oracle***
При возникновении проблемы при входе в мониторинг, которая возникает из-за таймаута при обращении в Oracle,
просто закончился пул соединений к Oracle, новые соединения не могут дождаться своей очереди и отваливаются по таймауту.
В этот момент можно сделать следующий запрос к БД:
select 'alter system disconnect session '''||v.SID||','||v.SERIAL#||''' immediate;' as command, v.USERNAME, v.MACHINE from v$session v where v.OSUSER = 'navi.autolocator.ru'';
Потом из колонки COMMAND скопировать получившиеся команды и выполнить их все.
При этом убиваются все соединения к Oracle от Navi и они возвращаются в пул.
После этого придется перезапустить сайт navi.autolocator.ru и службу Navi.Notifier
***
USER=oracle
LD_LIBRARY_PATH=/opt/oracle/product/18c/dbhomeXE/lib
ORACLE_BASE=/opt/oracle
MAIL=/var/spool/mail/oracle
PATH=/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/oracle/.local/bin:/home/oracle/bin:/opt/oracle/product/18c/dbhomeXE/bin
PWD=/home/oracle
HOME=/home/oracle
LOGNAME=oracle
ORACLE_HOME=/opt/oracle/product/18c/dbhomeXE
##################################################################################################

https://etogeek.ru/linux-partition-resize/
# LVM 

## Linux LVM extend disk vmware
Power off the virtual machine.
Edit the virtual machine settings and extend the virtual disk size. For more information, see Increasing the size of a virtual disk (1004047).
Power on the virtual machine.
Identify the device name, which is by default /dev/sda, and confirm the new size by running the command:
`fdisk -l`  
### Увеличение размера XFS partition
```
echo 1 > /sys/class/block/sdb/device/rescan
lsblk
yum install cloud-utils-growpart -y
growpart /dev/sdb 1
xfs_growfs -d /dev/sdb1
```
### LVM extend
```
echo 1 > /sys/class/block/sdb/device/rescan
lsblk
yum install cloud-utils-growpart -y
pvresize  /dev/sdb
lvextend -l +100%FREE /dev/datassdvg/datassdlv
xfs_growfs -d /dev/datassdvg/datassdlv
```
### Create a new primary partition  
Restart the virtual machine.
Run this command to verify that the changes were saved to the partition table and that the new partition has an 8e type:
`fdisk -l`  
Run this command to convert the new partition to a physical volume:  
Note: The number for the sda can change depending on system setup. Use the sda number that was created in step 5.
`pvcreate /dev/sda3`
Run this command to extend the physical volume:
`vgextend VolGroup00 /dev/sda3`
Note: To determine which volume group to extend, use the command vgdisplay.
Run this command to verify how many physical extents are available to the Volume Group:  
`vgdisplay VolGroup00 | grep "Free"`  
create logical volume:  
`lvcreate -n NAME -l 100%FREE vg0`
Run the following command to extend the Logical Volume:  
`lvextend -L+#G /dev/VolGroup00/LogVol00`  
`lvextend -l +100%FREE /dev/volgroup/logvol`  
Where # is the number of Free space in GB available as per the previous command. Use the full number output from Step 10 including any decimals.
Note: To determine which logical volume to extend, use the command lvdisplay.
Run the following command to expand the ext3 filesystem online, inside of the Logical Volume:
#### OLD### ext2online /dev/VolGroup00/LogVol00 (maybe xfs_growfs)
resize2fs /dev/VolGroup00/lvolroot
#for centos user bellow command:
xfs_growfs /dev/VolGroup00/lvolroot

lvextend -l +100%FREE /dev/volgroup/logvol
resize2fs /dev/mapper/centos_gitlab-root

##################################################################################################

Linux NTP
Останавливаем службу ntpd если она запущена:
service ntpd stop
Проверяем доступность ntp сервера
ntpdate -q 91.213.141.3
Подводим текущее время на сервере:
ntpdate 91.213.141.3
Правим конфиг ntp.conf в соответствии с вложением:
nano /etc/ntp.conf
Ставим демон в автозапуск
chkconfig ntpd on
Запускаем демона
service ntpd start
ntpq -p 

***CentOS***
yum install epel-release
**newest php**
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm


###########################################
LLDP linux centos CDP
for i in `ls /sys/class/net/ | grep enp` ;
      do echo "enabling lldp for interface: $i" ;
      lldptool set-lldp -i $i adminStatus=rxtx  ;
      lldptool -T -i $i -V  sysName enableTx=yes;
      lldptool -T -i $i -V  portDesc enableTx=yes ;
      lldptool -T -i $i -V  sysDesc enableTx=yes;
      lldptool -T -i $i -V sysCap enableTx=yes;
      lldptool -T -i $i -V mngAddr enableTx=yes;
done
###########################################


Cisco Nexus 1000V 
http://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus1000/sw/5_2_1_s_v_3_1_1/install_upgrade/workflow/nexus_1000v_r_5_2_1_s_v_3_1_1.html
brief: http://www.cisco.com/c/en/us/products/collateral/switches/nexus-1000v-switch-vmware-vsphere/guide_c07-556626.html

# WIRESHARK TCPDUMP TRAFFIC
#dump traffic into pcap file for wireshark
tcpdump -i <interface> -s 65535 -w <some-file>
tcpdump -i eth0 host 10.10.1.1


# Zabbix
## zabbix repo
http://repo.zabbix.com/zabbix/2.4/rhel/7/x86_64/
## zabbix prometheus alerts tiggers
Item types: HTTP agent  
URL: https://prometheus.server.lan/api/v1/query  
**Preprocessing**: JSONPath -> `$.data.result[0].value[1]`  
  
___
windows server 2008 2012
Network and sharing not work not reaspond
netsh interface tcp set global autotuninglevel=disabled


windows xp time zone
tzchange.exe /w 2015

CentOS 7
Postfix relay + Amavis-new 
yum --enablerepo=epel -y install amavisd-new clamav-server clamav-server-systemd
systemctl start clamd@amavisd 

***************************************************************
# логи
journalctl -lfu fail2ban  
journalctl --vacuum-size=1G  
journalctl --vacuum-time=1years  
### config journaclt
/еtc/systemd/journald.conf  
******
show banned IP addresses
ipset list
***************************************************************

***************************************************************
systemd systemctl
список сервисов
systemctl list-unit-files --type=service

drop-in unit file используется для предотвращения перезаписи файла при обновлении ПО
example on filebeat
mkdir /etc/systemd/system/filebeat.service.d
/etc/systemd/system/filebeat.service.d/log.conf
[Service]
Environment="BEAT_LOG_OPTS="
systemctl daemon-reload
systemctl restart filebeat
***************************************************************

# SQUID
http://timp87.blogspot.ru/2014/03/squid-ad.html
http://www.opennet.ru/openforum/vsluhforumID12/7201.html - DROPbox + squid


make distclean - сброс (перед повторной конфигурацией)

# Commons database's info
## Replication
*Synchronous* replication - process in that main DB (aka main/master/primary/publisher) will propogate changes to all standby nodes and receives a confirmation before the transaction is committed or marked as completed.  
*Asynchronous* replication, when the main node receives a transaction, it goes ahead to commit the transaction before propagating that change to standby nodes. This means that there will always be a lag between the main node and standbys.  
*Physical* replication - binary replication process that propogate all changes (include system's changes) to slave DBs.  
*Logical* replication - replication process that copy only data to slave DBs. That type preferred when moving between database versions, even if it is slightly more complicated to set up when compared to physical replication.  



# Key:value
# ETCD
* list all keys  
  `ETCDCTL_API=2 etcdctl ls --recursive`  
  `ETCDCTL_API=2 etcdctl get /service/p-layer/config`  
* list all members  
`etcdctl member list`  


# PostgreSQL
### Install
Official install guide [here](https://www.postgresql.org/download/linux/)  
```
sudo yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-7-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo yum install -y postgresql13-server
sudo /usr/pgsql-13/bin/postgresql-13-setup initdb
sudo systemctl enable postgresql-13
sudo systemctl start postgresql-13
```
## Replication  
*Streaming* replication - use WAL records which stream changes to the standbys in binary format as it is generated instead of waiting for the WAL file to be filled. Replicates only entire database. For congigure use *pg_basebackup*.  
*Logical* repllication - is achieved by the construction of a stream of logical data modifications from the WAL file (publication). Can use multi-directional data flow (one Publication many Subscriptors) and can copy individual tables instead of an entire database.   
## Performance tuning
_shared_buffers_ - inmemory buffer, set 25% from all RAM. In some case you can set 70% if all your DB fits inmemory.   
_work_mem_ - used for complex sorting. System will allocate work_mem * total sort operations for all users. If some operation need more memory then set in work_mem, than Postgres will create temporary file in *pgsql_tmp* directory. Look at *pgsql_tmp* in pick hours and make disisions, increas or not this parameter.   
_maintenance_work_mem_ - reserving memory for maintenance tasks like VACUUM, RESTORE, CREATE INDEX, ADD FOREIGN KEY, and ALTER TABLE.
_effective_cache_size_ -  
  
On-line generator PG config: https://pgconfig.org  
Presentation about postgres performance: https://pgconf.ru/en/2021/288825   
Presentation about shared memory (RUS): https://pgday.ru/presentation/145/596495320f25c.pdf  
Deep dive into postgres performance: https://erthalion.info/2019/12/06/postgresql-stay-curious/  
### Access
```
select * from pg_hba_file_rules ;
```
**********************
### where my configs located how find
`SHOW config_file;`
### where pg_hba file
`SHOW hba_file;`
### reload configurations
`select pg_reload_conf();`
### show currnet pg_hba
`table pg_hba_file_rules;`
**********************
/var/lib/pgpro/std-10/data/pg_hba.conf
**********************
### Performance
EXPLAIN ANALYZE SELECT * from DB_NAME;
### Show activity connections
`SELECT count(*),state FROM pg_stat_activity GROUP BY 2;`
### Clean activity connections
```
SELECT
    pg_terminate_backend(pid)
FROM
    pg_stat_activity
WHERE
    -- don't kill my own connection!
    pid <> pg_backend_pid()
    -- don't kill the connections to other databases
    AND datname = 'dev_aiagent_db'
    ;
```
#### Copy to file
`\copy (select * from pg_stat_activity) to /tmp/pg_stat_activity.csv csv;`  
### Grant privileges 
On all schemas
```
DO $do$
DECLARE
    sch text;
BEGIN
    FOR sch IN SELECT nspname FROM pg_namespace where nspname != 'pg_toast' 
    and nspname != 'pg_temp_1' and nspname != 'pg_toast_temp_1'
    and nspname != 'pg_statistic' and nspname != 'pg_catalog'
    and nspname != 'information_schema'
    LOOP
        EXECUTE format($$ GRANT USAGE ON SCHEMA %I TO layer_ro $$, sch);
        EXECUTE format($$ GRANT USAGE ON SCHEMA %I to layer_ro $$, sch);
        EXECUTE format($$ GRANT SELECT ON ALL SEQUENCES IN SCHEMA %I TO layer_ro $$, sch);
        EXECUTE format($$ GRANT SELECT ON ALL TABLES IN SCHEMA %I TO layer_ro $$, sch);

        EXECUTE format($$ ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO layer_ro $$, sch);
        EXECUTE format($$ ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON SEQUENCES TO layer_ro $$, sch);
    END LOOP;
END;
$do$;
```
Create read only user  
create psql user:  
```
postgres@server:~$ createuser --interactive 
Enter name of role to add: readonly
Shall the new role be a superuser? (y/n) n
Shall the new role be allowed to create databases? (y/n) n
Shall the new role be allowed to create more new roles? (y/n) n
```
  set password for user  
```
postgres=# alter user readonly with password 'readonly';
ALTER ROLE
```
grant all the needed privileges  
```
target_database=# GRANT CONNECT ON DATABASE target_database TO readonly;
GRANT
target_database=# GRANT USAGE ON SCHEMA public TO readonly ;
GRANT
target_database=# GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly ;
GRANT
```
  default privileges inheritance  
```
ALTER DEFAULT PRIVILEGES IN SCHEMA public
   GRANT SELECT ON TABLES TO 'username';
```

### Other
pg_config - показывает ключи с которыми PostgreSQL был собран
select pg_database_size('db_name'); - занимаемый разбер в байтах
`select pg_size_pretty(pg_database_size('db_name'));`  
`SELECT pg_size_pretty (pg_total_relation_size ('schema_name.table_name'));`  
pg_table_size();  
pg_indexes_size()  
pg_total_relation_size()  
### Top biggest size of tables 
```
SELECT nspname || '.' || relname AS "relation",
    pg_size_pretty(pg_total_relation_size(C.oid)) AS "total_size"
  FROM pg_class C
  LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
  WHERE nspname NOT IN ('pg_catalog', 'information_schema')
    AND C.relkind <> 'i'
    AND nspname !~ '^pg_toast'
  ORDER BY pg_total_relation_size(C.oid) DESC
  LIMIT 5;
```
### for postgrespro
/opt/pgpro/std-10/bin/pg_dump dbname > outfile
pg_dump -h 172.16.1.15 -U username -W dbname > outfile

## Backups
`pg_dump dbname > outfile`  
https://www.percona.com/blog/2018/09/25/postgresql-backup-strategy-enterprise-grade-environment/  
https://pgbackrest.org/release.html  
### Ускоряем бекап и восстановление
`pg_dump db | gzip > dump.gz`  
`zcat dump.gz | psql db`  
### dump of schema дамп схемы 
`pg_dump -Fp --schema-only --no-publications --no-subscription  -d new_warehouse_db > new_warehouse_db_dump.sql`
### dump of roles дамп ролей
`pg_dumpall --roles-only  -d new_warehouse_db > new_warehouse_db_roles.sql`
### dump certain table
`pg_dump -h localhost -p 5432 -p pg_username -d pg_db_name -t schema.table > table_dump.sql`
### restore
```
psql -U db_user db_name < dump_name.sql
pg_restore -d db_name /path/to/your/file/dump_name.tar -c -U db_user  
psql --set ON_ERROR_STOP=on dbname < infile
```
### DB an Role
#### First option
CREATE DATABASE dbname;
create user testuser;
alter user testuser with encrypted password 'Qwerty14';
grant all privileges on database dbname to testuser;
#### Second option
CREATE DATABASE dbname;
CREATE USER user1 password 'P@ssw0rd!';
ALTER ROLE "user1" WITH LOGIN;
GRANT ALL ON DATABASE dbname TO user1;

## Logical replication
#### Commands
* Публикации publications  
\dRp+  
* Подписки subscriptions  
\dRs+  
alter publication process_to_vr add table process.process_foods ;  
alter subscription mc_process_db1 refresh publication ;  
\dRp+ publication_name  
select * from pg_stat_replication ;  

## psql tips and triks
`\l` - list all databases  
`\c` - connect to database  
`\df` - display functions (procedures) in database  
`\dn` - show all schemas  
`\dt schema_name.*` - show all tables in schema  
`\d table_name` - show table structure

### Select examples
`select concat (table_schema, '.', table_name) as full_table_name from information_schema.tables where table_schema != 'pg_catalog' and table_schema != 'information_schema';`  
`SELECT string_agg(table_name::text, ', ') FROM information_schema.tables WHERE table_schema = 'store';`

###
#<< CentOS7 >>
sudo yum install postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo -i -u postgres (or sudo -u postgres psql)
psql -h localhost -U username database
###
`sudo vim /var/lib/pgsql/10/data/pg_hba.conf`  
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# "local" is for Unix domain socket connections only
local   all             all                                     trust
# IPv4 local connections:
host    all             all             127.0.0.1/32            md5
# IPv6 local connections:
host    all             all             ::1/128                 md5
```
###
```
CREATE ROLE redmine LOGIN ENCRYPTED PASSWORD 'my_secret' NOINHERIT VALID UNTIL 'infinity';
CREATE DATABASE redmine WITH ENCODING='UTF8' OWNER=redmine;
```
## timeouts 
`show idle_in_transaction_session_timeout;`  

###


# Microsoft Network Monitor 3.4
Conversation.ProcessName == "javaw.exe" - process capture

######################################################
######################################################
# MSSQL
*********************
##Activity Monitor
declare 
	@DbId as int = db_id(N'DATABASE NAME')

use [master];

select
	[now] = cast(sysdatetime() as datetime2(0))
/*,	[db_name] = db_name(er.[database_id]) */
,	es.session_id
,	er.[status]
,	er.command
/*,	[sql_command] = case when er.sql_handle is null then null else (select [text] from sys.dm_exec_sql_text(er.sql_handle)) end*/
,	er.percent_complete
,	er.[wait_resource]
,	er.blocking_session_id
,	es.[program_name]
,	es.[host_name]
,	es.[login_name]
,	es.[nt_user_name]
,	er.start_time
,	er.[user_id]
,	er.connection_id
from
	sys.dm_exec_requests er
inner join
	sys.dm_exec_sessions es
on	es.[session_id] = er.[session_id]
where
	er.database_id = @DbId
;
*********************
остановить восстановление базы
restore database DBNAME with recovery;
*********************



# HP Procurve
****for logging to console****
debug destination session
debug events
***
backup config
copy running-config tftp 10.1.14.38 gln-8206-sw-1_20170913.conf
***



# iperf
iperf -c 10.0.5.132 -i 1 -P 1 -w 1200



MS Exchange Mail server
send as distribution group:
Get-DistributionGroup "ro@invest.ru" | Add-ADPermission -User "username@mydomain.org" -ExtendedRights "Send As"
**************************************
get-mailbox -identity username
**************************************
проверка включена ли OWA
Get-CASMailbox username | fl Name,OWAEnabled
Set-CASMailbox username -OWAEnabled:$true
**************************************
Назначить политику тем у кого её нет:
Get-Mailbox -ResultSize Unlimited | Where { $_.RoleAssignmentPolicy -like $null} | Set-Mailbox –RoleAssignmentPolicy “Default Role Assignment Policy”


1С
Порты TCP
1560-1591 - для рабочего процесса;
1541 - для менеджера кластера;
1540 - для агента сервера (не обязательно, если центральный сервер кластера один).

```
(for %i in (*.wav) do @echo file '%i') > mylist.txt
ffmpeg.exe -f concat -safe 0 -i mylist.txt -c copy output.mp4
for %%a in ("input\*.*") do ffmpeg -i "%%a" -s hd720 -c:v libx264 -crf 23 -af "volume=30dB" "newfiles\%%~na.mp4"
pause
```
___
```
ffmpeg -i "Запись Конференция Jazz 2022-06-23_150034.webm" -c copy output.mp4
```


# OCI
## Thing image
### yum clean cache clean all
rm -rf /var/cache /var/log/dnf* /var/log/yum.*

# DOCKER

## Install
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker
#
`sudo groupadd docker`  
`sudo usermod -aG docker $USER`  

- to /etc/sysctl.conf:
_check:_  
``sysctl net.ipv4.ip_forward``
_enable_  
``sysctl -w net.ipv4.ip_forward=1``
_or_  
``echo 1 > /proc/sys/net/ipv4/ip_forward``
### Network ip4 forward enable
```
net.ipv4.ip_forward=1
sysctl -p 
```
### Network tuning
```
net.netfilter.nf_conntrack_sctp_timeout_established=3600
net.netfilter.nf_conntrack_tcp_timeout_established=3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait=60
net.ipv4.tcp_tw_reuse=1
```
### Build
``docker build -t jre8sms jre8-sms/.``
### Run
``docker run -it name_image command ``  
_example:_ ``docker run -it centos bash``

### Docker save to disk
_Compressing docker image:_  
``docker save myimage:latest | gzip > myimage_latest.tar.gz``  
_wihtout compressing save to disk:_  
``docker save -o fedora-all.tar fedora``  
_cherry-pick particular tags_  
``docker save -o ubuntu.tar ubuntu:lucid ubuntu:saucy``  

docker ps -all
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                      PORTS               NAMES
ee6f4d6e7f13        centos              "bash"              2 minutes ago       Exited (0) 14 seconds ago                       xenodochial_golick
docker commit -m "Apache + php" xenodochial_golick web


docker run --name glpidb -e MYSQL_ROOT_PASSWORD=RootSuperPass!@# -e MYSQL_DATABASE=glpidb -e MYSQL_USER='glpiuser'@'' -e MYSQL_PASSWORD=DBSuperPAss!@# -d mariadb:10.3

to shell container
docker exec -it glpidb(container name) bash

### remove all containers
```
docker rm -f $(docker ps -a | awk '{print $1}') 
docker rm -f $(docker ps -a -q)
docker rmi -f $(docker images harbor.12.somedomain.ru/security/*/* -q)
```
  
`docker update --restart=no abebf7571666`  
### save (export) container to disk (tarbol)
`docker save -o /home/setevoy/jenkins_2_7.tar jenkins`
### load (import) image from disk
`docker load -i jenkins_2_7.tar`  
### docker logs (path default)
`/var/lib/docker/containers/`  

## DOCKER TROUBLE
### ipv6 only
Need add the following to /etc/sysctl.conf:  
```
net.ipv4.ip_forward=1
systemctl restart network
sysctl -p
```

## DOCKERFILES example
FROM alpine:3.9 as builder
RUN apk update && apk add ca-certificates tzdata
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo/
COPY main /
CMD ["/main"]
### docker run example
docker run -d -p 9001:9001 --name syslog -v /var/log:/log mthenw/frontail -U sysadmin -P 12345678 -n 5000 /log/messages

## Docker Swarm
`docker node update p-b2b-swarm-sc-msk01 --availability drain`

## Docker registry
### curl
`curl https://username:password@privaterepo.yourdomain.com:5001/v2/image-name/tags/list`
# raid
## hpacucli  
```
hpacucli
ctrl all show config detail  
```

# Proxmox
### ISO upload to /var/lib/vz/template/iso  
```
configs:
/etc/pve/storage.cfg 
```
### import disk to vm
```
qm importdisk 152 astra-ald-v5-disk001.vmdk local-lvm --format qcow2
			  IDvm	name disk							convert to
```




# Ansible
By default ansible execute one task on all host but has limit 5 fork = [linner strategy](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/linear_strategy.html#linear-strategy). Ansible has other strategy: debug and free (fast).
## Execution strategy
By default 
### list all hostvars
ansible -i inventory pct-tst-tmp-01-centos-1.12.somedomain.local -m debug -a "var=hostvars[inventory_hostname]"
### ad-hoc online
`ansible -i p-vsh-gpu-sc-msk01.examples.lan, -m setup p-vsh-gpu-sc-msk01.examples.lan`  
`ansible -i p-vsh-gpu-sc-msk01.examples.lan, -m -a "filter=ansible_distribution*" p-vsh-gpu-sc-msk01.examples.lan`
#
ansible all -m file -a "mode=0660 path=/home/luna/rpms"

# show all available ansible's variables (can use hostvars)
ansible localhost -m setup
# default network properties
ansible -i mod-ib/test all -m setup -a "filter=ansible_default_ipv4"
# inventory
ansible-inventory --list # show all variables in all inventory
ansible-inventory --graph
# shell bash command
ansible -i inventory_file all -m shell -a "uptime"
ansible -i inventory_file all -m command -a "uptime" #not use shell, without env variables
# become with ad-hoc argument '-b'
# delete container
ansible all -i inventory/hosts -m docker_container -a "name=ldap-identity-provider state=absent"
#
specify private key
ansible_ssh_private_key_file=/home/user/.ssh/private.key
Read more: https://github.com/StreisandEffect/streisand/issues/923
#

# LDAP
`ldapsearch -LL -D someuser@somedomain.ru -W -H ldap://p-i-dc-sc-m01 -s sub -b DC=somedomain,DC=ru "(anr=sm_isearch)"`



# Git
https://product.hubspot.com/blog/git-and-github-tutorial-for-beginners
.git/info/exclude
git config --global core.autocrlf input  
## Merge
Merge one file or directory from other branch  
`git checkout dev views/default/menu.html` -  file menu.html from dev branch will merge to current branch  
### git shell executable 
git update-index --chmod=+x publish.sh  
### Filename too long  
git config --system core.longpaths true
### short sha1
git rev-parse --short HEAD
### only one branch
git clone -b release/1.1 --single-branch gitlab@gitlab.somedomain.ru:platform/data-access/rcrudl/sql-crud.git
## git submodules
add (create) submodule  
`git submodule add http://github.com/sciyoshi/pyfacebook.git external/pyfacebook`  
```
git submodule init
git submodule update
git submodule update --init --force --remote
```
## git show remote url
`git remote`
## git change remote url
`git remote set-url origin https://git.sberdevices.ru/public-repository/docker.git`
### Diff between branch and acestors 
`git diff --name-only release $(git merge-base master release) | egrep '(Sber|Adv|GCore|sber|KHA|SPB|MSK)'`
# GitLab
## Gilab CI
### regexp rules
`    - if: $CI_PIPELINE_SOURCE == "push" && ($GITLAB_USER_LOGIN =~ /^group_\d+_bot_.*$/ || $GITLAB_USER_NAME == $CLOUD_DEPLOY_TUZ_NAME)`
#### Kill all pending jobs for a project 
```ruby
# gitlab-rails console
p = Project.find_by_full_path(‘rogue-group/rogue-project’)
Ci::Pipeline.where(project_id: p.id).where(status: ‘pending’).each {|p| p.cancel}
exit
```

____



Windows 10 (activate service OpenSSH Authentication Agent)
ssh-keygen -t rsa -b 4096 -C "username@domain.com"
ssh-add 

Autolocator
Бесшовное переключение с LineBit (HQ-GW-3) на Netcom-R (HQ-GW-1)
terminal monitor 
conf t
interface tunnel 51
ip ospf cost 1000
interface port-channel 5
standby 110 priority 90
################################
OSPF ROUTES PREFERENCE
**1. Types route (from highest to lowest):
 1. Intra-area routes.
 2. Inter-area routes. 
 3. External Type-1 routes. 
 4. External Type-2 routes.
**2. Cost (from lowest to highest)
 based on bandwith
**3. If eaqual use multiple pathes

# SCHEMA PROTOCOL (ANY)
``shchema://user:password@domainame.zone:port/URI``
examples:  
```
https://username:QwePassword@yandex.ru:8080/path/to/document/index.php?arg1=data&arg2=putin
ssh://username:QwePassword@192.168.109.201:2221:/path
```


# Download all web site 
``wget -e robots=off -b --recursive -l 10 --no-clobber --page-requisites --convert-links --no-parent https://tvzvezda.ru/``




# BASH bash
#!/usr/bin/env bash

## bash loop
for i in {1..4}; do ssh -o loglevel=ERROR username@nginx-srv$i ;done

### bash example redis bitnami run.sh
```
#!/bin/bash

# shellcheck disable=SC1091

set -o errexit
set -o nounset
set -o pipefail
# set -o xtrace # Uncomment this line for debugging purposes

# Load Redis environment variables
. /opt/bitnami/scripts/redis-env.sh

# Load libraries
. /opt/bitnami/scripts/libos.sh
. /opt/bitnami/scripts/libredis.sh

# Constants
REDIS_EXTRA_FLAGS=${REDIS_EXTRA_FLAGS:-}

# Parse CLI flags to pass to the 'redis-server' call
args=("$REDIS_BASE_DIR/etc/redis.conf" "--daemonize" "no")
# Add flags specified via the 'REDIS_EXTRA_FLAGS' environment variable
read -r -a extra_flags <<< "$REDIS_EXTRA_FLAGS"
[[ "${#extra_flags[@]}" -gt 0 ]] && args+=("${extra_flags[@]}")
# Add flags passed to this script
args+=("$@")

info "** Starting Redis **"
if am_i_root; then
    exec gosu "$REDIS_DAEMON_USER" redis-server "${args[@]}"
else
    exec redis-server "${args[@]}"
fi
```

### Loop цикл
i=0; while [ $i -lt 10 ]; do curl https://123-namespace.s3.somedomaincloud.ru/cb-person-pub/224201  --output /dev/null; let i++;done

RUBY RAILS
>>rails version
bundle exec rails -v

#Подсчитать количество файлов
cd /path/to/folder_with_huge_number_of_files1
ls -f | wc -l

#############################
# ELK Elastic Logstash Kibana#
https://gist.github.com/ruanbekker/e8a09604b14f37e8d2f743a87b930f93 cheatsheet-elasticsearch.md
#|||||||||||||||||||||||||||#
Kibana version
curl -XGET 'http://localhost:9200'
### Cluster status
curl -u username:password -k -i https://p-mm-elasticsearch-master-1:9200/_cluster/health?pretty


# curl
## curl mTLS client cert
$ curl --cert client.crt --key client.key --cacert ca.crt https://myserver.internal.net:443
### download
curl -u anonymous:digitalenergy -T file.file https://colba.decs.online/remote.php/dav/files/anonymous/anonymous_upload/file.file
curl -v -u admin:admin123 --upload-file frontend.zip http://nexus.somedomain.local/nexus-2.7.0/service/local/repositories/releases/content/ru/voskhod/scc/scc.portal/%version%/frontend.zip
curl -u admin:admin123 -T org/postgresql/main/postgresql-42.2.4.jar http://nexus.somedomain.local/nexus-2.7.0/service/local/repositories/thirdparty/content/org/postgresql/postgresql/42.2.4/postgresql-42.2.4.jar  
### POST
- For posting data:  
``curl --data "param1=value1&param2=value2" http://hostname/resource``  
- For file upload:  
``curl --form "fileupload=@filename.txt" http://hostname/resource``  
- RESTful HTTP Post:  
``curl -X POST -d @filename http://hostname/resource``
- For logging into a site (auth):  
```
curl -d "username=admin&password=admin&submit=Login" --dump-header headers http://localhost/Login
curl -L -b headers http://localhost/
```
### GET
- with JSON:  
``curl -i -H "Accept: application/json" -H "Content-Type: application/json" -X GET http://hostname/resource``  
- with XML:  
``curl -H "Accept: application/xml" -H "Content-Type: application/xml" -X GET http://hostname/resource``  
## curl with proxy
curl -x proxy.somedomain.ru:3128 -I -XGET https://api.amplitude.com
curl -O http://site.name.ru/filename.gz -x proxy.somedomain.ru:3128 
### curl ignore proxy
`curl --noproxy '*' http://www.stackoverflow.com`
### timing details aka latency measuring
```
echo "time_namelookup: %{time_namelookup}\n
time_connect: %{time_connect}\n
time_appconnect: %{time_appconnect}\n
time_pretransfer: %{time_pretransfer}\n
time_redirect: %{time_redirect}\n
time_starttransfer: %{time_starttransfer}\n
———\n
time_total: %{time_total}\n
\n
ADDITIONAL INFORMATION\n
http_version: %{http_version}\n
num_connects: %{num_connects}\n
size_download: %{size_download}\n
size_header: %{size_header}\n
size_request: %{size_request}\n
size_upload: %{size_upload}\n
speed_download: %{speed_download}\n
speed_upload: %{speed_upload}\n" > curl-format.txt
curl -w "@curl-format.txt" -o /dev/null -s http://wordpress.com/
```
same per one line `curl -X POST -d @file server:port -w %{time_connect}:%{time_starttransfer}:%{time_total}`  or `curl -o /dev/null -s -w 'Establish Connection: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n' https://uma.media/metainfo/yandex_feed/`  
more detail look here https://blog.josephscott.org/2011/10/14/timing-details-with-curl/  

grep 
whithout comments and blank lines
grep -v '^\s*$\|^\s*\#' filebeat.yml 
# печать вывод совпадений
grep -Po "([\w-]*[a-zA-Z])*\:([\w0-9]).*" tmp.txt
cat tmp.txt
image: harbor.12.somedomain.ru/security/security-services/access-manager-initializer:1.6.5-00
image: harbor.12.somedomain.ru/security/security-services/authenticator:1.6.4-00

#
#OPENVPN openvpn easy-rsa
#
yum install -y openvpn easy-rsa
cd /etc/openvpn/
mkdir easy-rsa
cp -R /usr/share/easy-rsa/3/* easy-rsa/
cd easy-rsa/
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req SERVERNAME nopass
./easyrsa sign-req server SERVERNAME
./easyrsa gen-dh
openvpn --genkey --secret ta.key
mv ta.key pki/private/
# Generate cert for client
./easyrsa gen-req CLIENTNAME nopass
./easyrsa sign-req client CLIENTNAME
#configuration file /etc/openvpn/server/server.conf
port 11940
proto udp
dev tun
script-security 2
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/erp-mod-ib-router.crt
dh /etc/openvpn/easy-rsa/pki/dh.pem
server 10.20.20.0 255.255.255.0
keepalive 10 120
persist-key
persist-tun
reneg-sec 300
status /var/log/openvpn/openvpn-status.log
log         /var/log/openvpn/openvpn.log
log-append  /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
push "route 10.8.34.0 255.255.255.0"
cipher AES-256-CBC
# autostart daemon and start now
systemctl enable --now openvpn-server@server
# маршрутизация VPN сервера: необходимо разрешить форвард для доступа клиентов Openvpn к локальной сети (10.20.20 - пул openvpn, 10.8.34 - LAN)
iptables -A FORWARD -s 10.20.20.0/24 -d 10.8.34.0/24 -j ACCEPT
iptables -A FORWARD -d 10.20.20.0/24 -s 10.8.34.0/24 -j ACCEPT

https://serveradmin.ru/nastroyka-openvpn-na-centos-7/#_openvpn_8212_TAP_TUN


# mutible ports несколько портов
iptables -A INPUT -p tcp  --match multiport --dports 110,143,993,995 -j ACCEPT
# iptables commentary
iptables -A INPUT -p tcp --dport 80 -m comment --comment "block HTTPD access - " -j DROP
# masquerade
iptables -t nat -I POSTROUTING -o eth0 -s 10.20.23.2 -j MASQUERADE
# mega rule
iptables -I FORWARD -s 192.168.109.254,192.168.109.251 -d 10.215.0.204,10.215.0.202 -p tcp --match multiport --dports 21,7700,8080 -m comment --comment "to miniSMEV access" -j ACCEPT
# change destination ip DNAT
iptables -t nat -A PREROUTING -i eth0 -p tcp -d 10.215.0.31 --dport 2022 -j DNAT --to-destination 192.168.109.253:22
# маршуртизация в сети:
# 1. Best practis IMHO: статичиский маршрут на ближайшем рутере с дальнейшей его редистрибьюцией в диманическую маршрутизацию + ACL на GW для целевой подсети
# 2. Статический маршрут на рутере терминирующем целевую подсеть (GW)
# 3. Статический маршрут на всех необходимых хостах. Like this:
echo "10.20.20.0/24 via 10.8.34.13" > /etc/sysconfig/network-scripts/route-eth0
#
# disable internet
iptables -A OUTPUT -s any -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -s any -d 172.16.0.0/12 -j ACCEPT
iptables -A OUTPUT -s any -d 192.168.0.0/16 -j ACCEPT
iptables -A OUTPUT -s any -d 0.0.0.0/0 -j DROP
#
#
yum install -y openvpn easy-rsa
mkdir -p /etc/openvpn/easy-rsa
cp -R /usr/share/easy-rsa/3/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa/
./easyrsa init-pki
./easyrsa build-ca nopass
#
# Example overlay network config base on OPENVPN
#
#mode server
#topology subnet
#port 1194
#proto udp
#dev tun0
#verb 3
#cipher AES-256-CBC
#ca ca.crt
#key vpn.key
#cert vpn.crt
#dh dh.pem
#tls-server
#keepalive 10 60
#persist-key
#persist-tun
#ifconfig-pool-persist ipp.txt 0
#client-config-dir ccd
#status openvpn.log 2
#user nobody
#group users
#server 10.23.0.0 255.255.255.0
#client-to-client


#
# SED
#
[Sed one-liners](https://gist.github.com/chunyan/b426e4b696ff3e7b9afb)  
`sed -i s/^SELINUX=.*$/SELINUX=permissive/ /etc/selinux/config`  
`sed -i --regexp-extended 's@.*/([0-9]{8})/@\1@'`
- recursively  
```
find /home/www/ -type f -exec \
    sed -i 's/subdomainA\.example\.com/subdomainB.example.com/g' {} +
echo "James Bond" | sed -E 's/(.*) (.*)/The name is \2, \1 \2./'
```
`sed -i.bak  's/\.sh\s\-c\s\$2\s\-b\s\$3\R$/\1 bmanagement/g' launch.sh`  
### remove range of lines from file
`sed -i 10,20d dump.sql`  
will remove range from 10 to 20 (include) rows from dump.sql file  
  
  
remove tail rows from file
`head -n -10 process_goods_result.sql > process_goods_result_edit.sql`

# 
# AWK
#
``` 
cat image_builded.txt
version=0.7.0
branch=develop
gitlab.somedomain.ru:5050/layer/video-rotor:develop-0.7.0-11b692aa
```
```
# print only tag image
awk -F":" '{print $3}' image_builded.txt | awk /./
```
# Wireguard
```
yum update
yum install epel-release
curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
yum install wireguard-dkms wireguard-tools
#check modules
>#dkms status
#yum install kernel-headers-"$(uname -r)" kernel-devel-"$(uname -r)" -y
wg genkey > private
ip link add wg0 type wireguard
ip addr add 10.0.0.1/24 dev wg0
wg set wg0 private-key ./private
ip link set wg0 up
```


# Maven
maven mvn
#build jar file
# сохраняет либы в локальном кеше
mvn clean install -Dmaven.test.skip=true 
# не сохраняет либы
mvn clean package

# NPM
## .npmrc
progress=false
email=jenkins@somedomain.ru
_auth=PaSSw0rD
always-auth=true
@openapitools:registry=http://nexus.12.somedomain.ru/repository/npm-internal/


ng npm angular
# angular set package manager
ng set --global packageManager=yarn


spec web
location.origin = DOMString protocol:hostname:port (example http://localhost:8080)
location.pathname = часть после первого / (включая его) следующего за доменом (портом)


show my ip web like 2ip.ru
https://wtfismyip.com/text


Astra Linux Смоленск
pdpl-user -i 63 USERNAME



# BASH
`$0` - имя скрипта  
`$1` - firs argument, `$2` - second etc.  
`$#` - count arguments  
`$@` - all arguments is delimited spaces  
`$&` - статус выполнения последней команды  
Пример скрипта с выпобором:  
```
#!/bin/bash

echo -n "Продолжить? (y/n) "

read item
case "$item" in
    y|Y) echo "Ввели «y», продолжаем..."
        ;;
    n|N) echo "Ввели «n», завершаем..."
        exit 0
        ;;
    *) echo "Ничего не ввели. Выполняем действие по умолчанию..."
        ;;
esac
```
### именованные аргументы named arguments
```
RESTORE=0
ENCRYPT=1

ARGPAD=1 # Если в коде где-то требуются оставшиеся аргументы (например список файлов) их можно получить прибавив этот 'отступ'
for argument in ${@}; do
    case $argument in
        -r | --restore )
            RESTORE=1
            ARGPAD=$(($ARGPAD + 1))
            ;;

        -e=* | --encrypt=* )
            encrypt=${argument##*=}

            if [ "$encrypt" == "non-encrypt" -o $encrypt == 0 ]; then
                ENCRYPT=0
            fi

            ARGPAD=$(($ARGPAD + 1))
            ;;

        -* )
            ARGPAD=$(($ARGPAD + 1))
            ;;
    esac
done
```
###

date "+%Y%m%d"

# Jenkins
Q. Почему стоит хранить jenkins files в проекте с исходным кодом а не выносить с отдельный?  
A. Потому что в зависимости от релизной ветки бывают разные варинаты сборок, т.о. если jenkins файл лежит в проекте он может отличаться от ветки к ветки, тем самым мы имеем один jenkins job просто выбираем ветку (gitParameter), в противном случае количество jenkins job'ов и jenkins file'ов прямо пропорциональной различным сборкам.   
Jenkins - Nodes - Slave_agent_name - Script Console  
```
println System.getenv("LANG")  
println "mvn -version".execute().text
```

# Powershell
### execution policy
# для текущей terminal сессии:
Set-ExecutionPolicy Unrestricted -Scope Process
# like grep
Select-Strint -Pattern "what_do_match"


# Yandex Cloud
### list all images id  
`yc compute image list --folder-id standard-images`  


# cron
```
minute  hour    day     month  day
             (month)          (week)
```
### Посмотреть все задачи у всех пользователей
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done
### Log cron jobs
`* * * * * myjob.sh >> /var/log/myjob.log 2>&1`


# OpenShift
Bash completion on mac  
```
oc completion bash > /usr/local/etc/bash_completion.d/oc_bash_completion.sh   
source /usr/local/etc/bash_completion.d/oc_bash_completion.sh
```
* install oc client  
`yum install openshift-clients`
* show my login
`oc whoami`
* Show my registry clusters  
`oc config get-clusters`
* Show all contexts (clusters where I registered)  
`oc config get-contexts`
* Rename current context
`oc config rename-context $(oc config current-context) NEW_NAME_CONTEXT`
* Change context   
`oc config use-context context_name`
* list all projects
`oc projects`
* change project
`oc project PROJECT_NAME`
* list all deployments
`oc get deployments`
* get status or erorrs (may use | grep message )
`oc get deployment DEPLOY_NAME -o yaml`
* get info error logs events pod
`oc describe pod <pod-id>`
* get debug errors & evens
`oc debug statefulset/<stateful_name>`
* запуск пода run pod
`oc run db-test-postgresql-client --rm --tty -i --restart='Never' --namespace layer --image docker.io/bitnami/postgresql:11.11.0-debian-10-r62 --limits="cpu=200m,memory=0.2Gi" --env="PASSWORD=$POSTGRES_PASSWORD" --command -- psql --host db-test-postgresql -U postgres -d lumiere_cinema_db -p 5432`
* delete all evicted pods
``oc get pods | grep Evicted | awk '{print $1}' | xargs oc delete pod``  
* delete all failed pods
`oc delete pod --field-selector=status.phase=Failed`
* Filter status pods
`oc get pods | grep CrashLoopBackOff | awk '{print $1}'`
* Create new project
```
oc new-project hello-openshift \
    --description="This is an example project" \
    --display-name="Hello OpenShift"
```
* fix deployer  
`oc policy add-role-to-user edit -z deployer`  
* Get SA token
```
# oc describe sa deployer
Name:                deployer
Namespace:           p-resetpassword
Labels:              <none>
Annotations:         <none>
Image pull secrets:  deployer-dockercfg-4t9mk
Mountable secrets:   deployer-dockercfg-4t9mk
Tokens:              deployer-token-l6llf
Events:              <none>
# oc describe secret deployer-token-l6llf
```


## Networking
* Port forward  
`kubectl port-forward service/showcase-api 8080:8080`  

### Routes
* show default ingress domain  
`oc get ingresses.config/cluster -o jsonpath={.spec.domain}`  


## Heml
### Notes
``template`` is an action (control structure), and not a function
### List all installed charts
``helm list``  
### Отступы
{{- variable }} обрезает предшествующие пробелы;  
{{ variable -}} обрезает последующие пробелы;  
{{- variable -}} — оба варианта.  


### minishift credentials
login: docker
pass: tcuser
switch to root:
sudo su


# HDD SSD
Show current propertyes  
`tune2fs -l`  
Reserved block count × Block size  
`tune2fs -r $((10*1024*1024/4096)) /dev/sda1`  
Set reserved block 1%   
`tune2fs -m 1 /dev/sba1`  


# Kubernetes k8s
Megge inject combaine объединение configmap and secrets
https://github.com/kubernetes/kubernetes/issues/30716  
если в двух словах то никак, либо secret либо config map, если сложнее то внутри контейнера можно юзать скрипт осуществляющий модмену маски в конфигурационном файле, т.е. пароли в секретах в env пода, а envsub меняет маску в конфиге из configmap'a https://www.padok.fr/en/blog/helm-kubernetes-configmap-secret
Если же предпочесть     другую стратегию, не используюя environment gitlab'a а хранить все конфиги в git то нужно смотреть в сторону Mozilla SOPS.
https://swiety-python.blogspot.com/2021/01/managing-secrets-in-gitlab.html  
Gitlab CI registry-pull
https://devopstales.github.io/home/k8s-imagepullsecret-patcher/  

# GPG (pgp) key crypto
https://habr.com/ru/post/358182/  
Генерация ключей
``gpg --full-generate-key``  
Экспорт ключей  
``gpg --export-secret-key SOMEKEYID > key_name.gpg``  
Импорт ключей  
``gpg --import key_name.gpg``  

# One liners oneliners
## set rlimit per pid
`ps axuw |grep process_name |grep -v grep |awk '{ print "prlimit -n60000 -p " $2 }'`
## curl
#### Speed latency http
curl -w "dns_resolution: %{time_namelookup}, tcp_established: %{time_connect}, ssl_handshake_done: %{time_appconnect}, TTFB: %{time_starttransfer}\n" -o /dev/null -s https://cloudflare-dns.com  
## grep
### Last match последнее совпадение
grep PATTERN nginx.log | tail -1    
### Nginx top request
logfile="/var/log/nginx/balancer.access.log"
grep "^$(cat "${logfile}" | cut -d' ' -f1 | sort | uniq -c | sort -nr | head -n 1 | awk -F' ' '{print $2}') " "${logfile}" | cut -d' ' -f7 | sort | uniq -c | sort -nr | head -n 50
### cat
multiline echo to file
```
cat <<EOF > /var/www/html/index.html
<html>
My any text body
</html>
EOF
```
## Network scan
`echo > /dev/tcp/172.16.0.12/5043 && echo "Open"`

~/.bash_profile - user mode (when login console or ssh)  
~/.bashrc - interactive mode non-login (when run bash command or run bash script)  
### Adding directory to the PATH 
``PATH=$PATH:$HOME/bin:/usr/local/bin``  
``export PATH``  

# Ingress Nginx
### IP Whitelist for location
https://stackoverflow.com/questions/58925853/kubernetes-ingress-whitelist-ip-for-path  
```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: frontend-admin
  namespace: default
  labels:
    app: frontend
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/16"
spec:
  tls:
    - hosts:
        - frontend.example.com
      secretName: frontend-tls
  rules:
    - host: frontend.example.com
      http:
        paths:
          - path: /admin
            backend:
              serviceName: api
              servicePort: 8000
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: frontend-all
  namespace: default
  labels:
    app: frontend
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
    - hosts:
        - frontend.example.com
      secretName: frontend-tls
  rules:
    - host: frontend.example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: frontend
              servicePort: 80
          - path: /api
            backend:
              serviceName: api
              servicePort: 8000
          - path: /staticfiles
            backend:
              serviceName: api
              servicePort: 80
```



https://github.com/mozilla/sops/issues/370
cat $KEY | gpg --batch --import
echo $PASSPHRASE | gpg --batch --always-trust --yes --passphrase-fd 0 --pinentry-mode=loopback -s $(mktemp)

gpg-connect-agent reloadagent /bye

# SonarQube
### Notes
https://github.com/mc1arke/sonarqube-community-branch-plugin


## Too many open files
There are two types of ulimit settings:  
The **hard** limit is the maximum value that is allowed for the soft limit. 
Any changes to the hard limit require root access.
The **soft** limit is the value that Linux uses to limit the system resources for running processes. 
The soft limit cannot be greater than the hard limit.
### How many files I can open?  
``cat /proc/sys/fs/file-max``  
### How may file open currnet time?
``cat /proc/sys/fs/file-nr``  
1 - open files now  
2 - opened but not used  
3 - max open file I can  
### Increase max open files for user
``/etc/security/limits.conf``
www-data        soft    nofile          32000
www-data        hard    nofile          64000
### Increase max open files for system
``vi /etc/sysctl.conf``  
fs.file-max = 999999  
применить настройки  
``sysctl -p``
### Настраиваем ulimit
Текущее состояние настроек ulimit можно посмотреть: ulimit -a  
Открываем файл:  
``sudo vi /etc/security/limits.conf``  
и добавляем с него следующую строку:  
``* - nofile 999999``
Устанавливаем для текущего шелла ограничение: ``ulimit -n 999999``  
Перезапускаем апачу для применения настроек: /etc/init.d/httpd restart (или постфикс: /etc/init.d/postfix restart )  
Заходим под юзером апача (или постфикса: su postfix -s /bin/sh) и удостоверяемся, что настройки новые:  
``su apache -s /bin/sh``   
```
for pid in `pidof nginx`; do echo "$(< /proc/$pid/cmdline)"; egrep 'files|Limit' /proc/$pid/limits; echo "Currently open files: $(ls -1 /proc/$pid/fd | wc -l)"; echo; done
```

# Redis
### connect to redis
``redis-cli -p 6903 -a your_secret_pass``  
### memory info
``info memory``      
### get all keys
``reids-cli --scan``
### get key's value
``MGET``
### delete/remove key:value
``DEL keyname``  
### Redis: OOM command not allowed when used memory > ‘maxmemory
https://ma.ttias.be/redis-oom-command-not-allowed-used-memory-maxmemory/  

# GitLab
DIND image from private registry  
https://docs.gitlab.com/ee/ci/docker/using_docker_images.html#define-an-image-from-a-private-container-registry  
you must use DOCKER_AUTH_CONFIG variables

# File Storages 
## S3 Object Storage
### s3cmd
`s3cmd --configure`  
List of buckets (список бакетов)  
`s3cmd ls`  
Create bucket (создать бакет)  
`s3cmd mb s3://bucket`  
Upload object to bucket (загрузить объект в бакет)  
`s3cmd put local_file.txt s3://bucket/object`  
Download object  
`s3cmd get s3://bucket/object local_file.txt`  
Remove object  
`s3cmd del s3://bucket/object`  

# Trace 
strace -f -e trace=file tmux

# Data fromat
### Linux
`cp ./running_app/ app_bkp_$(date +'%Y%m%d')`

# Mattermost
## API examples
### Login
`curl -i -d '{"login_id":"someone@nowhere.com","password":"thisisabadpassword"}' https://myserver.company.com/api/v4/users/login`
### Get teams
`curl -S -H 'Authorization: Bearer tokenTokenToken' https://myserver.company.com/api/v4/teams | jq`
### Get user by email
`curl -sS -H 'Authorization: Bearer tokenTokenToken' https://myserver.company.com/api/v4/users/email/username@company.com | jq`
#### Which channel user is
```
userid=`curl -sS -H 'Authorization: Bearer tokenTokenToken' https://myserver.company.com/api/v4/users/email/username@company.com | jq -r '.id'`
curl -sS -H 'Authorization: Bearer tokenTokenToken' https://myserver.company.com/api/v4/users/$userid/teams/8yfs9fjym7dwudxh3g6z4znefo/channels | jq '.[].display_name'
```


# rsyslog
Рекомендованные настройки
```
# An on-disk queue is created for this action. If the remote host is
# down, messages are spooled to disk and sent when it is up again.
$ActionQueueFileName ForwardToSIEM # unique name prefix for spool files
$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
$ActionQueueType LinkedList   # run asynchronously
$ActionResumeRetryCount -1    # infinite retries if host is down
```
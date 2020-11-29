#!/bin/bash
#A script to collect artifacts from a Linux host
version="version 0.982"
#@rebootuser

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mUNFI DFIR Linux Collection Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# $version\e[00m\n"
echo -e "\e[00;33m# Example: ./EnumerationScript.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-s 	Supply user password for sudo checks (INSECURE)"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
echo -e "\e[00;31m#########################################################\e[00m"		
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mUNFI Linux DFIR Artifacts Collection Script\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;31m#########################################################\e[00m"  

}

debug_info()
{
echo "[-] Debug Information" 

if [ "$keyword" ]; then 
	echo "[+] Searching for the keyword $keyword in conf, php, ini and log files" 
fi

if [ "$report" ]; then 
	echo "[+] Report name = $report" 
fi

if [ "$export" ]; then 
	echo "[+] Export location = $export" 
fi

if [ "$thorough" ]; then 
	echo "[+] Thorough tests = Enabled" 
else 
	echo -e "\e[00;33m[+] Thorough tests = Disabled\e[00m" 
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinuxIR-Enumeration-FIleExports-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
fi

if [ "$sudopass" ]; then 
  echo -e "\e[00;35m[+] Please enter password - INSECURE - really only for CTF use!\e[00m"
  read -s userpassword
  echo 
fi

#remove any pre-existing collection folder
rm -r /tmp/Linux-IR*



#create collection folder for enumeration data
today=$(date +"%m_%d_%Y")
host=$(hostname)
mkdir /tmp/Linux-IR-$today-$host



who=`whoami  2>/dev/null`
echo -e "\nMake sure you are running as root or admin user"
echo -e "YOU ARE RUNNING THIS SCRIPT AS $who"


echo -e "\e\n[00;33mCollection started at:"; date 
echo -e "\e[00m\n" 
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='aria2c\|arp\|ash\|awk\|base64\|bash\|busybox\|cat\|chmod\|chown\|cp\|csh\|curl\|cut\|dash\|date\|dd\|diff\|dmsetup\|docker\|ed\|emacs\|env\|expand\|expect\|file\|find\|flock\|fmt\|fold\|ftp\|gawk\|gdb\|gimp\|git\|grep\|head\|ht\|iftop\|ionice\|ip$\|irb\|jjs\|jq\|jrunscript\|ksh\|ld.so\|ldconfig\|less\|logsave\|lua\|make\|man\|mawk\|more\|mv\|mysql\|nano\|nawk\|nc\|netcat\|nice\|nl\|nmap\|node\|od\|openssl\|perl\|pg\|php\|pic\|pico\|python\|readelf\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-parts\|rvim\|scp\|script\|sed\|setarch\|sftp\|sh\|shuf\|socat\|sort\|sqlite3\|ssh$\|start-stop-daemon\|stdbuf\|strace\|systemctl\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xxd\|zip\|zsh'

#SYSTEM INFORMATION CODE
system_info()
{
echo -e "\e[00;33m### SYSTEM INFORMATION ##############################################\e[00m" 

#basic kernel info
mkdir /tmp/Linux-IR-$today-$host/system_information
unameinfo=`uname -a  | tee /tmp/Linux-IR-$today-$host/system_information/kernel_information.txt 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31m[-] Kernel information:\e[00m\n$unameinfo" 
  echo -e "\n" 
fi

procver=`cat /proc/version | tee /tmp/Linux-IR-$today-$host/system_information/version_information.txt 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31m[-] Kernel information (continued):\e[00m\n$procver" 
  echo -e "\n" 
fi

#search all *-release files for version info
release=`cat /etc/*-release  | tee /tmp/Linux-IR-$today-$host/system_information/release_information.txt 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31m[-] Specific release information:\e[00m\n$release" 
  echo -e "\n" 
fi

#target hostname info
hostnamed=`hostname | tee /tmp/Linux-IR-$today-$host/system_information/hostname.txt 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31m[-] Hostname:\e[00m\n$hostnamed" 
  echo -e "\n" 
fi
}


#USER INFORMATION CODE
user_info()
{
echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/user_information

#current user details
currusr=`id  | tee /tmp/Linux-IR-$today-$host/user_information/current_user.txt 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31m[-] Current user/group info:\e[00m\n$currusr" 
  echo -e "\n"
fi

#last logged on user information
lastlogedonusrs=`lastlog | tee /tmp/Linux-IR-$today-$host/user_information/last_loggedon_users.txt 2>/dev/null |grep -v "Never"  2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31m[-] Users that have previously logged onto the system:\e[00m\n$lastlogedonusrs" 
  echo -e "\n" 
fi

#who else is logged on
loggedonusrs=`w  | tee /tmp/Linux-IR-$today-$host/user_information/currently_loggedon_users.txt 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31m[-] Who else is logged on:\e[00m\n$loggedonusrs" 
  echo -e "\n"
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd | tee /tmp/Linux-IR-$today-$host/user_information/groups.txt 2>/dev/null);do id $i;done  2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31m[-] Group memberships:\e[00m\n$groupinfo" 
  echo -e "\n"
fi

#find admin users
adm_users=$(echo -e "$grpinfo" | grep "(adm)") | tee /tmp/Linux-IR-$today-$host/user_information/admin_users.txt
if [[ ! -z $adm_users ]];
  then
    echo -e "\e[00;31m[-] Admin users:\e[00m\n$adm_users" 
    echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd | tee /tmp/Linux-IR-$today-$host/user_information/hashes_in_etc_passwd.txt 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33m[+] password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" 
  echo -e "\n"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd | tee /tmp/Linux-IR-$today-$host/user_information/etc_passwd_content.txt 2>/dev/null`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/passwd:\e[00m\n$readpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow | tee /tmp/Linux-IR-$today-$host/user_information/etc_shadow.txt 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m[+] Shadow file contents\e[00m\n$readshadow" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd | tee /tmp/Linux-IR-$today-$host/user_information/master_passwd.txt 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m[+] master.passwd file contents\e[00m\n$readmasterpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
fi

#all root accounts (uid 0)
superman=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' | tee /tmp/Linux-IR-$today-$host/user_information/root_accts.txt
  echo -e "\n" 2>/dev/null`
if [ "$superman" ]; then
  echo -e "\e[00;31m[-] Super user account(s):\e[00m\n$superman" 
fi

#important sudoers
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" | tee /tmp/Linux-IR-$today-$host/user_information/important_sudoers.txt 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31m[-] Sudoers configuration (condensed):\e[00m$sudoers"
  echo -e "\n"
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
fi

#check if sudo works without supplying a password
sudoperms=`echo '' | sudo -S -l -k | tee /tmp/Linux-IR-$today-$host/user_information/sudoers_without_password.txt 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33m[+] We can sudo without supplying a password!\e[00m\n$sudoperms" 
  echo -e "\n"
fi

#check sudo perms - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudoauth=`echo $userpassword | sudo -S -l -k | tee /tmp/Linux-IR-$today-$host/user_information/sudoers_with_password.txt 2>/dev/null`
      if [ "$sudoauth" ]; then
        echo -e "\e[00;33m[+] We can sudo when supplying a password!\e[00m\n$sudoauth" 
        echo -e "\n"
      fi
    fi
fi

##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudopermscheck=`echo $userpassword | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist | tee /tmp/Linux-IR-$today-$host/user_information/sudoers_with_password.txt 2>/dev/null`
      if [ "$sudopermscheck" ]; then
        echo -e "\e[00;33m[-] Possible sudo pwnage!\e[00m\n$sudopermscheck" 
        echo -e "\n"
      fi
    fi
fi

#known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
sudopwnage=`echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist | tee /tmp/Linux-IR-$today-$host/user_information/breakout_binaries.txt 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m[+] Possible sudo pwnage!\e[00m\n$sudopwnage" 
  echo -e "\n"
fi

#check past sudo usage
whohasbeensudo=`find /home -name .sudo_as_admin_successful | tee /tmp/Linux-IR-$today-$host/user_information/previous_sudo_users.txt 2>/dev/null`
if [ "$whohasbeensudo" ]; then
  echo -e "\e[00;31m[-] Accounts that have recently used sudo:\e[00m\n$whohasbeensudo" 
  echo -e "\n"
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ | tee /tmp/Linux-IR-$today-$host/user_information/root_home_directory_read.txt 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m[+] We can read root's home directory!\e[00m\n$rthmdir" 
  echo -e "\n"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ | tee /tmp/Linux-IR-$today-$host/user_information/home_directory_permissions.txt 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31m[-] Are permissions on /home directories lax:\e[00m\n$homedirperms" 
  echo -e "\n"
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {}  | tee /tmp/Linux-IR-$today-$host/user_information/files_not_owned_by_user_but_group_writeable.txt 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "\e[00;31m[-] Files not owned by user but writable by group:\e[00m\n$grfilesall" 
    echo -e "\n"
  fi
fi

#looks for files that belong to us
if [ "$thorough" = "1" ]; then
  ourfilesall=`find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {}  | tee /tmp/Linux-IR-$today-$host/user_information/files_not_belonging_to_current_user.txt 2>/dev/null`
  if [ "$ourfilesall" ]; then
    echo -e "\e[00;31m[-] Files owned by our user:\e[00m\n$ourfilesall" 
    echo -e "\n"
  fi
fi

#looks for hidden files
if [ "$thorough" = "1" ]; then
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; | tee /tmp/Linux-IR-$today-$host/user_information/hidden_files.txt 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    echo -e "\e[00;31m[-] Hidden files:\e[00m\n$hiddenfiles" 
    echo -e "\n"
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; | tee /tmp/Linux-IR-$today-$host/user_information/globally_readable_files.txt 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\e[00;31m[-] World-readable files within /home:\e[00m\n$wrfileshm" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	fi
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ | tee /tmp/Linux-IR-$today-$host/user_information/home_directory_contents.txt 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\e[00;31m[-] Home directory contents:\e[00m\n$homedircontents" 
		echo -e "\n" 
	fi
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} | tee /tmp/Linux-IR-$today-$host/user_information/accessible_SSH_files.txt 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		echo -e "\e[00;31m[-] SSH keys/host information found in the following locations:\e[00m\n$sshfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	fi
fi

#root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}' | tee /tmp/Linux-IR-$today-$host/user_information/root_ssh_login.txt`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31m[-] Root is allowed to login via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" 
  echo -e "\n"
fi
}


#ENVIRONMENTAL VARIABLE CODE
environmental_info()
{
echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/environment_artifacts

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' | tee /tmp/Linux-IR-$today-$host/environment_artifacts/env_var.txt 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m[-] Environment information:\e[00m\n$envinfo" 
  echo -e "\n"
fi

#check if selinux is enabled
sestatus=`sestatus | tee /tmp/Linux-IR-$today-$host/environment_artifacts/selinux.txt 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "\e[00;31m[-] SELinux seems to be present:\e[00m\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH | tee /tmp/Linux-IR-$today-$host/environment_artifacts/env_path.txt 2>/dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls -ld $(echo $PATH | tr ":" " ")`
  echo -e "\e[00;31m[-] Path information:\e[00m\n$pathinfo" 
  echo -e "$pathswriteable"
  echo -e "\n"
fi

#lists available shells
shellinfo=`cat /etc/shells | tee /tmp/Linux-IR-$today-$host/environment_artifacts/available_shells.txt 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31m[-] Available shells:\e[00m\n$shellinfo" 
  echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S | tee /tmp/Linux-IR-$today-$host/environment_artifacts/default_umask_octal.txt 2>/dev/null; umask >  /tmp/Linux-IR-$today-$host/environment_artifacts/default_umask.txt 2>/dev/null`
if [ "$umaskvalue" ]; then
  echo -e "\e[00;31m[-] Current umask value:\e[00m\n$umaskvalue" 
  echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=`grep -i "^UMASK" /etc/login.defs | tee /tmp/Linux-IR-$today-$host/environment_artifacts/umask_login_def.txt 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31m[-] umask value as specified in /etc/login.defs:\e[00m\n$umaskdef" 
  echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs grep -i "^UMASK" /etc/login.defs | tee /tmp/Linux-IR-$today-$host/environment_artifacts/password_policy_login_def.txt 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
fi
}



job_info()
{
echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/persistence_artifacts

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/system_cron_jobs.txt  2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31m[-] Cron jobs:\e[00m\n$cronjobs" 
  echo -e "\n"
fi



#contab contents
crontabvalue=`cat /etc/crontab | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/crontab_content.txt  2>/dev/null`
if [ "$crontabvalue" ]; then
  echo -e "\e[00;31m[-] Crontab contents:\e[00m\n$crontabvalue" 
  echo -e "\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/crontab_content.txt 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31m[-] Anything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar" 
  echo -e "\n"
fi

anacronjobs=`ls -la /etc/anacrontab | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/anacrontab_listing.txt 2>/dev/null; cat /etc/anacrontab | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/anacron_config.txt 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31m[-] Anacron jobs and associated file permissions:\e[00m\n$anacronjobs" 
  echo -e "\n"
fi

anacrontab=`ls -la /var/spool/anacron | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/anacron_job_listing.txt 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31m[-] When were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab" 
  echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u | tee /tmp/Linux-IR-$today-$host/persistence_artifacts/cron_job_all_users.txt 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31m[-] Jobs held by all users:\e[00m\n$cronother" 
  echo -e "\n"
fi

# list systemd timers
systemctl list-timers --all > /tmp/Linux-IR-$today-$host/persistence_artifacts/systemd_timers.txt
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all  2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="\e[2mEnable thorough tests to see inactive timers\e[00m"
fi
if [ "$systemdtimers" ]; then
  echo -e "\e[00;31m[-] Systemd timers:\e[00m\n$systemdtimers\n$info"
  echo -e "\n"
fi

}


#NETWORKING CODE
networking_info()
{
echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/networking_artifacts

#nic information
nicinfo=`/sbin/ifconfig -a | tee /tmp/Linux-IR-$today-$host/networking_artifacts/ifconfig.txt 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfo" 
  echo -e "\n"
fi

#nic information (using ip)
nicinfoip=`/sbin/ip a | tee /tmp/Linux-IR-$today-$host/networking_artifacts/ip_info.txt 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
  echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfoip" 
  echo -e "\n"
fi

arpinfo=`arp -a | tee /tmp/Linux-IR-$today-$host/networking_artifacts/arp_info.txt 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfo" 
  echo -e "\n"
fi



#dns settings
nsinfo=`grep "nameserver" /etc/resolv.conf | tee /tmp/Linux-IR-$today-$host/networking_artifacts/dns_nameservers.txt 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfo" 
  echo -e "\n"
fi

nsinfosysd=`systemd-resolve --status | tee /tmp/Linux-IR-$today-$host/networking_artifacts/dns_info.txt 2>/dev/null`
if [ "$nsinfosysd" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfosysd" 
  echo -e "\n"
fi

#default route configuration
defroute=`route | tee /tmp/Linux-IR-$today-$host/networking_artifacts/route_info.txt 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defroute" 
  echo -e "\n"
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default | tee /tmp/Linux-IR-$today-$host/networking_artifacts/route_info_from_ip.txt `
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defrouteip" 
  echo -e "\n"
fi

#listening TCP
tcpservs=`netstat -ntpl | tee /tmp/Linux-IR-$today-$host/networking_artifacts/tcp_processes_established.txt 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservs" 
  echo -e "\n"
fi

tcpservsip=`ss -arn | tee /tmp/Linux-IR-$today-$host/networking_artifacts/static_socket_all_processes.txt 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservsip" 
  echo -e "\n"
fi

#listening UDP
udpservs=`netstat -nupl | tee /tmp/Linux-IR-$today-$host/networking_artifacts/udp_processes.txt 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31m[-] Listening UDP:\e[00m\n$udpservs" 
  echo -e "\n"
fi

}


# SERVICES CODE
services_info()
{
echo -e "\e[00;33m### SERVICES #############################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/services_artifacts

#running processes
psaux=`ps aux  | tee /tmp/Linux-IR-$today-$host/services_artifacts/running_processes.txt 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;31m[-] Running processes:\e[00m\n$psaux" 
  echo -e "\n"
fi

#lookup process binary path and permissisons
procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la | tee /tmp/Linux-IR-$today-$host/services_artifacts/running_proceses_with_permissions.txt 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  echo -e "\e[00;31m[-] Process binaries and associated permissions (from above list):\e[00m\n$procperm" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/inetd.conf:\e[00m\n$inetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la | tee /tmp/Linux-IR-$today-$host/services_artifacts/inetd_binary_perm.txt 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related inetd binary permissions:\e[00m\n$inetdbinperms" 
  echo -e "\n"
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/xinetd.conf:\e[00m\n$xinetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
fi

xinetdincd=`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null 
  echo -e "\n"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related xinetd binary permissions:\e[00m\n$xinetdbinperms" 
  echo -e "\n"
fi

initdread=`ls -la /etc/init.d | tee /tmp/Linux-IR-$today-$host/services_artifacts/init.d_binary_perm.txt 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ binary permissions:\e[00m\n$initdread" 
  echo -e "\n"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null | tee /tmp/Linux-IR-$today-$host/services_artifacts/non_root_init.d_files.txt`
if [ "$initdperms" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ files not belonging to root:\e[00m\n$initdperms" 
  echo -e "\n"
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null | tee /tmp/Linux-IR-$today-$host/services_artifacts/init.d_files_binary_permissions.txt`
if [ "$rcdread" ]; then
  echo -e "\e[00;31m[-] /etc/rc.d/init.d binary permissions:\e[00m\n$rcdread" 
  echo -e "\n"
fi



#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "\e[00;31m[-] /usr/local/etc/rc.d files not belonging to root:\e[00m\n$usrrcdperms" 
  echo -e "\n"
fi

initread=`ls -la /etc/init/ | tee /tmp/Linux-IR-$today-$host/services_artifacts/etc_init_upstart_config_permissions.txt 2>/dev/null`
if [ "$initread" ]; then
  echo -e "\e[00;31m[-] /etc/init/ config file permissions:\e[00m\n$initread"
  echo -e "\n"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null | tee /tmp/Linux-IR-$today-$host/services_artifacts/upstart_scripts_not_root_related.txt`
if [ "$initperms" ]; then
   echo -e "\e[00;31m[-] /etc/init/ config files not belonging to root:\e[00m\n$initperms"
   echo -e "\n"
fi

systemdread=`ls -lthR /lib/systemd/ 2>/dev/null | tee /tmp/Linux-IR-$today-$host/services_artifacts/lib_systemd_config_file_permissions.txt`
if [ "$systemdread" ]; then
  echo -e "\e[00;31m[-] /lib/systemd/* config file permissions:\e[00m\n$systemdread"
  echo -e "\n"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null | tee /tmp/Linux-IR-$today-$host/services_artifacts/lib_systemd_config_file_perms_not_root.txt`
if [ "$systemdperms" ]; then
   echo -e "\e[00;33m[+] /lib/systemd/* config files not belonging to root:\e[00m\n$systemdperms"
   echo -e "\n"
fi
}


#SOFTWARE CODE
software_configs()
{
echo -e "\e[00;33m### SOFTWARE #############################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/software_artifacts

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V  2>/dev/null| grep "Sudo version" 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/sudo_version.txt`
if [ "$sudover" ]; then
  echo -e "\e[00;31m[-] Sudo version:\e[00m\n$sudover" 
  echo -e "\n"
fi

#mysql details - if installed
mysqlver=`mysql --version | tee /tmp/Linux-IR-$today-$host/software_artifacts/mysql_version.txt 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31m[-] MYSQL version:\e[00m\n$mysqlver" 
  echo -e "\n"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/mysql_root_root_connection.txt `
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect" 
  echo -e "\n"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version | tee /tmp/Linux-IR-$today-$host/software_artifacts/mysql_root_no_passwd_connection.txt 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass" 
  echo -e "\n"
fi

#postgres details - if installed
postgver=`psql -V | tee /tmp/Linux-IR-$today-$host/software_artifacts/postgres_version.txt 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31m[-] Postgres version:\e[00m\n$postgver" 
  echo -e "\n"
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres -w template0 -c 'select version()' 2>/dev/null | grep version | tee /tmp/Linux-IR-$today-$host/software_artifacts/postgres_db_connect_user_postgres.txt`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1" 
  echo -e "\n"
fi

postcon11=`psql -U postgres -w template1 -c 'select version()' 2>/dev/null | grep version | tee /tmp/Linux-IR-$today-$host/software_artifacts/postgres_db_connect_user_postgres2.txt`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11" 
  echo -e "\n"
fi


#apache details - if installed
apachever=`apache2 -v 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_artifacts.txt; httpd -v 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/httpd_version.txt`
if [ "$apachever" ]; then
  echo -e "\e[00;31m[-] Apache version:\e[00m\n$apachever" 
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars |awk '{sub(/.*\export /,"")}1' | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_user_group.txt  2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31m[-] Apache user configuration:\e[00m\n$apacheusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_modules.txt; httpd -M 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_modules2.txt`
if [ "$apachemodules" ]; then
  echo -e "\e[00;31m[-] Installed Apache modules:\e[00m\n$apachemodules" 
  echo -e "\n"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/htpasswd.txt`
if [ "$htpasswd" ]; then
    echo -e "\e[00;33m[-] htpasswd found - could contain passwords:\e[00m\n$htpasswd"
    echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apachehomedirs=`ls -alhR /var/www/ 2>/dev/null| tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_home_dirs.txt; ls -alhR /srv/www/htdocs/ 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_home_dirs2.txt; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_home_dirs3.txt; ls -alhR /opt/lampp/htdocs/ 2>/dev/null | tee /tmp/Linux-IR-$today-$host/software_artifacts/apache_home_dirs3.txt`
  if [ "$apachehomedirs" ]; then
    echo -e "\e[00;31m[-] www home dir contents:\e[00m\n$apachehomedirs" 
    echo -e "\n"
  fi
fi

}

# FILE ARTIFACTS CODE
interesting_files()
{
echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m" 
mkdir /tmp/Linux-IR-$today-$host/file_artifacts

#checks to see if various files are installed
echo -e "\e[00;31m[-] Useful file locations:\e[00m" ; which nc 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/nc_filepath.txt; which netcat 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/netcat_filepath.txt; which wget 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/wget_filepath.txt; which nmap 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/nmap_filepath.txt; which gcc 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/gcc_filepath.txt; which curl 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/curl_filepath.txt
echo -e "\n" 

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/dpkg_compiler.txt && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/installed_compiler_yum.txt`
if [ "$compiler" ]; then
  echo -e "\e[00;31m[-] Installed compilers:\e[00m\n$compiler" 
  echo -e "\n"
fi

#manual check - lists out sensitive file permissions, can we read/modify etc.
echo -e "\e[00;31m[-] Permissions for sensitive files:\e[00m" ; ls -la /etc/passwd 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/etc_passwd_permissions.txt; ls -la /etc/group 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/group_permissions.txt; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/etc_shadow_permissions.txt; ls -la /etc/master.passwd 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/etc_master_passwd_permissions.txt
echo -e "\n" 

#search for suid files
allsuid=`find / -perm -4000 -type f 2>/dev/null`
findsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/suid_files_with_permissions.txt`
if [ "$findsuid" ]; then
  echo -e "\e[00;31m[-] SUID files:\e[00m\n$findsuid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsuid" ]; then
  mkdir $format/suid-files/ 2>/dev/null
  for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} + 2>/dev/null | grep -w $binarylist 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/interesting_suid_files.txt`
if [ "$intsuid" ]; then
  echo -e "\e[00;33m[+] Possibly interesting SUID files:\e[00m\n$intsuid" 
  echo -e "\n"
fi

#lists world-writable suid files
wwsuid=`find $allsuid -perm -4002 -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/suid_writeable_files_with_permissions.txt`
if [ "$wwsuid" ]; then
  echo -e "\e[00;33m[+] World-writable SUID files:\e[00m\n$wwsuid" 
  echo -e "\n"
fi

#lists world-writable suid files owned by root
wwsuidrt=`find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/suid_files_owned_by_root.txt`
if [ "$wwsuidrt" ]; then
  echo -e "\e[00;33m[+] World-writable SUID files owned by root:\e[00m\n$wwsuidrt" 
  echo -e "\n"
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2>/dev/null`
findsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/sgid_files_with_permissions.txt`
if [ "$findsgid" ]; then
  echo -e "\e[00;31m[-] SGID files:\e[00m\n$findsgid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsgid" ]; then
  mkdir $format/sgid-files/ 2>/dev/null
  for i in $findsgid; do cp $i $format/sgid-files/; done 2>/dev/null
fi

#list of 'interesting' sgid files
intsgid=`find $allsgid -perm -2000 -type f  -exec ls -la {} + 2>/dev/null | grep -w $binarylist 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/interesting_sgid_files.txt`
if [ "$intsgid" ]; then
  echo -e "\e[00;33m[+] Possibly interesting SGID files:\e[00m\n$intsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files
wwsgid=`find $allsgid -perm -2002 -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/sgid_writeable_files_with_permissions.txt`
if [ "$wwsgid" ]; then
  echo -e "\e[00;33m[+] World-writable SGID files:\e[00m\n$wwsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files owned by root
wwsgidrt=`find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/sgid_files_owned_by_root.txt`
if [ "$wwsgidrt" ]; then
  echo -e "\e[00;33m[+] World-writable SGID files owned by root:\e[00m\n$wwsgidrt" 
  echo -e "\n"
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/file_posix_capabilities.txt || /sbin/getcap -r / 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/file_with_posix_capabilities.txt`
if [ "$fileswithcaps" ]; then
  echo -e "\e[00;31m[+] Files with POSIX capabilities set:\e[00m\n$fileswithcaps"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fileswithcaps" ]; then
  mkdir $format/files_with_capabilities/ 2>/dev/null
  for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
fi

#search /etc/security/capability.conf for users associated capabilities
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/users_with_specific_posix_capabilities.txt`
if [ "$userswithcaps" ]; then
  echo -e "\e[00;33m[+] Users with specific POSIX capabilities:\e[00m\n$userswithcaps"
  echo -e "\n"
fi

if [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		echo -e "\e[00;33m[+] Capabilities associated with the current user:\e[00m\n$matchedcaps"
		echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			echo -e "\e[00;33m[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):\e[00m\n$matchedfiles"
			echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			echo -e "\e[00;33m[+] Permissions of files with the same capabilities associated with the current user:\e[00m\n$matchedfilesperms"
			echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					echo -e "\e[00;33m[+] User/Group writable files with the same capabilities associated with the current user:\e[00m\n$writablematchedfiles"
					echo -e "\n"
				fi
			fi
		fi
	fi
fi

#search for private keys 
if [ "$thorough" = "1" ]; then
privatekeyfiles=`grep -rl "PRIVATE KEY-----" /home 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		echo -e "\e[00;33m[+] Private SSH keys found!:\e[00m\n$privatekeyfiles"
  		echo -e "\n"
	fi
fi

#look for AWS keys 
if [ "$thorough" = "1" ]; then
awskeyfiles=`grep -rli "aws_secret_access_key" /home 2>/dev/null`
	if [ "$awskeyfiles" ]; then
  		echo -e "\e[00;33m[+] AWS secret keys found!:\e[00m\n$awskeyfiles"
  		echo -e "\n"
	fi
fi

#look for git credential files 
if [ "$thorough" = "1" ]; then
gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
	if [ "$gitcredfiles" ]; then
  		echo -e "\e[00;33m[+] Git credentials saved on the machine!:\e[00m\n$gitcredfiles"
  		echo -e "\n"
	fi
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "\e[00;31m[-] World-writable files (excluding /proc and /sys):\e[00m\n$wwfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	fi
fi

#are any .plan files accessible in /home (could contain useful information)
bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {}  -exec cat {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/plan_file_permissions_contents.txt;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31m[-] Plan file permissions and contents:\e[00m\n$bsdusrplan" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null  -exec cat {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/rhost_config_file_with_specific_posix_capabilities.txt`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;33m[+] rhost config file(s) and file contents:\e[00m\n$rhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} + 2>/dev/null  -exec cat {} 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/rhosts_config_and_file_contents.txt`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;33m[+] rhost config file(s) and file contents:\e[00m\n$bsdrhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null  -exec cat {} 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/hosts_equiv_file_and_contents.txt`
if [ "$rhostssys" ]; then
  echo -e "\e[00;33m[+] Hosts.equiv file and contents: \e[00m\n$rhostssys" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/NFS_config_details.txt; cat /etc/exports 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/NFS_config_contents.txt`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31m[-] NFS config details: \e[00m\n$nfsexports" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
fi


#displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/fstab_contents.txt`
  if [ "$fstab" ]; then
    echo -e "\e[00;31m[-] NFS displaying partitions and filesystems\e[00m"
    echo -e "$fstab"
    echo -e "\n"
  fi


#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null; `
if [ "$fstab" ]; then
  echo -e "\e[00;33m[+] Looks like there are credentials in /etc/fstab!\e[00m\n$fstab"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m[+] /etc/fstab contains a credentials file!\e[00m\n$fstabcred" 
    echo -e "\n"
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.conf files as no keyword was entered\n" 
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/keyword_search_conf_files.txt`
    if [ "$confkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .conf files" 
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.php files as no keyword was entered\n" 
  else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/keyword_search_php_files.txt`
    if [ "$phpkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):\e[00m\n$phpkey" 
      echo -e "\n" 
     else 
  echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels):\e[00m" 
  echo -e "'$keyword' not found in any .php files" 
  echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.log files as no keyword was entered\n" 
  else
    logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/keyword_search_log_files.txt`
    if [ "$logkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$logkey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.ini files as no keyword was entered\n" 
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/keyword_search_ini_files.txt`
    if [ "$inikey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .ini files" 
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/etc_conf_files.txt`
if [ "$allconf" ]; then
  echo -e "\e[00;31m[-] All *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/user_history_files.txt`
if [ "$usrhist" ]; then
  echo -e "\e[00;31m[-] Current user's history files:\e[00m\n$usrhist" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/root_history_files.txt`
if [ "$roothist" ]; then
  echo -e "\e[00;33m[+] Root's history files are accessible!\e[00m\n$roothist" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
fi

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/bash_history_files.txt`
if [ "$checkbashhist" ]; then
  echo -e "\e[00;31m[-] Location and contents (if accessible) of .bash_history file(s):\e[00m\n$checkbashhist"
  echo -e "\n"
fi

#any .bak files that may be of interest
bakfiles=`find / -name *.bak -type f 2</dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/possible_backup_files.txt`
if [ "$bakfiles" ]; then
  echo -e "\e[00;31m[-] Location and Permissions (if accessible) of .bak file(s):\e[00m"
  for bak in `echo $bakfiles`; do ls -la $bak;done
  echo -e "\n"
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/interesting_mail_artifacts.txt`
if [ "$readmail" ]; then
  echo -e "\e[00;31m[-] Any interesting mail in /var/mail:\e[00m\n$readmail" 
  echo -e "\n"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null | tee /tmp/Linux-IR-$today-$host/file_artifacts/root_mail.txt`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m[+] We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
fi
}



# DOCKER CODE
docker_checks()
{

mkdir /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts

#specific checks - check to see if we're in a docker container
dockercontainer=`find / -name "*dockerenv*" -exec ls -la {}  2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/dockerenv.txt`
if [ "$dockercontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a Docker container:\e[00m\n$dockercontainer" 
  echo -e "\n"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/docker_version.txt; docker ps -a 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/docker_lxc_containers.txt`
if [ "$dockerhost" ]; then
  echo -e "\e[00;33m[+] Looks like we're hosting Docker:\e[00m\n$dockerhost" 
  echo -e "\n"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/docker_group_id.txt`
if [ "$dockergrp" ]; then
  echo -e "\e[00;33m[+] We're a member of the (docker) group - could possibly misuse these rights!\e[00m\n$dockergrp" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/docker_files.txt`
if [ "$dockerfiles" ]; then
  echo -e "\e[00;31m[-] Anything juicy in the Dockerfile:\e[00m\n$dockerfiles" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} + 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/docker_compose_yml.txt`
if [ "$dockeryml" ]; then
  echo -e "\e[00;31m[-] Anything juicy in docker-compose.yml:\e[00m\n$dockeryml" 
  echo -e "\n"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/lxd_container.txt`
if [ "$lxccontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a lxc container:\e[00m\n$lxccontainer"
  echo -e "\n"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep -i lxd 2>/dev/null | tee /tmp/Linux-IR-$today-$host/docker_lxc_container_artifacts/lxd_container_groups.txt`
if [ "$lxdgroup" ]; then
  echo -e "\e[00;33m[+] We're a member of the (lxd) group - could possibly misuse these rights!\e[00m\n$lxdgroup"
  echo -e "\n"
fi
}

footer()
{
echo -e "\e[00;33m########## ARTIFACTS COLLECTION COMPLETE ###############\e[00m" 
}

call_each()
{
  header
  debug_info
  system_info
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "h:k:r:e:st" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript

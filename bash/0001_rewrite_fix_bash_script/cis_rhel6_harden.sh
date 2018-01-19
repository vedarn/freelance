#!/bin/bash

RHL6=$(grep -c " 6\." /etc/redhat-release)
RHL7=$(grep -c " 7\." /etc/redhat-release)

# set variables
FSTAB=/etc/fstab
PRELINK=/etc/sysconfig/prelink
NETWORK=/etc/sysconfig/network
AUDIT=/etc/audit/auditd.conf
AUDITRULES=/etc/audit/audit.rules
GRUB=/etc/grub.conf
AUTOFS=/etc/sysconfig/autofs
AUTOFSCK=/etc/sysconfig/autofsck
SYSCONFIGINIT=/etc/sysconfig/init
SYSCTL=/etc/sysctl.conf
LIMITSCONF=/etc/security/limits.conf
HOSTSDENY=/etc/hosts.deny
IPTABLES=/etc/sysconfig/iptables
RSYSLOG=/etc/rsyslog.conf
VARLOG=/var/log
SSHCONFIG=/etc/ssh/sshd_config
SYSTEMAUTH=/etc/pam.d/system-auth
PASSWDAUTH=/etc/pam.d/password-auth
LOGINDEFS=/etc/login.defs
DEFUSERADD=/etc/default/useradd
PASSWD=/etc/passwd
SHADOW=/etc/shadow
GROUP=/etc/group
PAMSU=/etc/pam.d/su
YUM_CONF=/etc/yum.conf
YUM_REPOS_DIR=/etc/yum.repos.d


# Function usage: show usage message and exit
usage(){
  echo "Usage:"
  echo "$0 without params performs check hardening and report fails"
  echo "$0 -execute checks and fix hardening fails"
}

# colorize fail, pass and other output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NO_COLOR='\033[0m'

echo_fail() {
    echo -e "${RED}fail${NO_COLOR}"
}

echo_pass() {
    echo -e "${GREEN}pass${NO_COLOR}"
}

echo_other() {
    echo -e "${YELLOW}${1}${NO_COLOR}"
}

# 1.1.1 Ensure mounting of uncommon filesystems is disabled
check_uncommonfs(){
  echo
  #~ echo "1.1.1 Ensure mounting of uncommon filesystems is disabled"
  BLACKLIST=/etc/modprobe.d/CIS.conf
  uncommonfs=([0]=cramfs [1]=freevxfs [2]=jffs2 [3]=hfs [4]=hfsplus [5]=squashfs [6]=udf [7]=FAT)
  #~ uncommonfs="cramfs freevxfs jffs2 hfs hfsplus squashfs udf FAT"
  # Check if blacklist file exists
  if [ -f $BLACKLIST ]
  then
    i=1
    for fs in "${uncommonfs[@]}"
    #~ for fs in `echo $uncommonfs`
    do
      echo
      echo "1.1.1.$i Ensure mounting of $fs filesystems is disabled"
      # Check if module is installed
      check_mod=`modprobe -lv $fs | grep -c $fs`
      if [ $check_mod -gt 0 ]
      then
        # If yes check if it is in the blacklist file
        check_blacklist=`grep -c $fs $BLACKLIST`
        if [ $check_blacklist -gt 0 ]
        then
          echo_pass
        else
          echo_fail
        fi
      else
        # This means that module is not installed
        echo_other "$fs module not installed"
      fi
      i=$(($i+1))
    done
  else
    echo_fail
  fi
}

# Fix 1.1.1
fix_uncommonfs(){
  echo
  #~ echo "1.1.1 Ensure mounting of uncommon filesystems is disabled"
  BLACKLIST=/etc/modprobe.d/CIS.conf
  uncommonfs=([0]=cramfs [1]=freevxfs [2]=jffs2 [3]=hfs [4]=hfsplus [5]=squashfs [6]=udf [7]=FAT)
  # Check if blacklist file exists
  if [ -f $BLACKLIST ]
  then
    i=1
    for fs in ${uncommonfs[@]}
    do
      echo
      echo "1.1.1.$i Ensure mounting of $fs filesystems is disabled"
      # Check if module is installed
      check_mod=`modprobe -lv $fs | grep -c $fs`
      if [ $check_mod -gt 0 ]
      then
        # If yes check if it is in the blacklist file
        check_blacklist=`grep -c $fs $BLACKLIST`
        if [ $check_blacklist -gt 0 ]
        then
          echo_pass
        else
          echo "install $fs /bin/true" >>$BLACKLIST
          echo_pass
        fi
      else
        # This means that module is not installed
        echo "$fs module not installed"
    echo "install $fs /bin/true" >>$BLACKLIST
      fi
      i=$(($i+1))
    done
  else
    touch $BLACKLIST
    i=1
    for fs in ${uncommonfs[@]}
    do
      echo
      echo "1.1.1.$i Ensure mounting of $fs filesystems is disabled"
      # Check if module is installed
      check_mod=`modprobe -lv $fs | grep -c $fs`
      if [ $check_mod -gt 0 ]
      then
        echo "install $fs /bin/true" >>$BLACKLIST
        echo_pass
      else
        # This means that module is not installed
        echo "$fs module not installed"
    echo "install $fs /bin/true" >>$BLACKLIST
      fi
      i=$(($i+1))
    done
  fi
}

# 1.1  Check fs mount options
#~ check_fsmountopts(){
  #~ echo
  #~ echo "1.1 Ensure nodev nosuid and noexec options set on /tmp and /dev/shm partitions"
  #~ # Check if already mounted with required options
  #~ i=3
  #~ for opt in nodev nosuid noexec
  #~ do
    #~ # Checking for /tmp filesystem
    #~ mount | grep -w "/tmp" | grep $opt >/dev/null 2>&1
    #~ if [ $? -eq 0 ]
    #~ then
      #~ echo
      #~ echo "1.1.$i Ensure $opt option set on /tmp partition"
      #~ echo_pass
      #~ i=$(($i+1))
    #~ else
      #~ echo
      #~ echo "1.1.$i Ensure $opt option set on /tmp partition"
      #~ echo_fail
      #~ i=$(($i+1))
    #~ fi
  #~ done
  #~ j=15
  #~ for opt in nodev nosuid noexec
  #~ do
    #~ # Checking for /dev/shm filesystem
    #~ mount | grep -w "/dev/shm" | grep $opt >/dev/null 2>&1
    #~ if [ $? -eq 0 ]
    #~ then
      #~ echo
      #~ echo "1.1.$j Ensure $opt option set on /dev/shm partition"
      #~ echo_pass
      #~ j=$(($j+1))
    #~ else
      #~ echo
      #~ echo "1.1.$j Ensure $opt option set on /dev/shm partition"
      #~ echo_fail
      #~ j=$(($j+1))
    #~ fi
  #~ done
#~ }

#~ # 1.1  Check fs mount options
check_fsmountopts(){
  echo
  echo "1.1 Ensure nodev nosuid and noexec options set on /tmp /var/tmp /dev/shm partitions"
  # Check if already mounted with required options
  i=1
  for partition in /tmp /var/tmp /dev/shm
  do
      for opt in nodev nosuid noexec
      do
        # Checking for /tmp filesystem
        echo
        echo "1.1.$i Ensure $opt option set on ${partition} partition"
        mount | grep -w "${partition}" | grep $opt >/dev/null 2>&1
        if [ $? -eq 0 ]
        then
          echo_pass
        else
          echo_fail
        fi
        i=$(($i+1))
      done
  done
  
  echo
  echo "1.1.$i Ensure nodev option set on /home partition"
  mount | grep -w "/home" | grep nodev >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 1.1
fix_fsmountopts(){
  echo
  echo "1.1 Ensure nodev nosuid and noexec options set on /tmp and /dev/shm partitions"
  # Check if already mounted with required options
  i=3
  for opt in nodev nosuid noexec
  do
    # Checking for /tmp filesystem
    mount | grep -w "/tmp" | grep $opt >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo
      echo "1.1.$i Ensure $opt option set on /tmp partition"
      echo_pass
      i=$(($i+1))
    else
      echo
      echo "1.1.$i Ensure $opt option set on /tmp partition"
      ed $FSTAB << END >/dev/null 2>&1
/\/tmp/
s/defaults/defaults,$opt/
.
w
q
END
      echo "pass - Re-mount of /tmp filesystem needed"
      i=$(($i+1))
    fi
  done
  j=15
  for opt in nodev nosuid noexec
  do
    # Checking for /dev/shm filesystem
    mount | grep -w "/dev/shm" | grep $opt >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo
      echo "1.1.$j Ensure $opt option set on /dev/shm partition"
      echo_pass
      j=$(($j+1))
    else
      echo
      echo "1.1.$j Ensure $opt option set on /dev/shm partition"
      ed $FSTAB << END >/dev/null
/\/dev\/shm/
s/defaults/defaults,$opt/
.
w
q
END
      echo "pass - Re-mount of /dev/shm filesystem needed"
      j=$(($j+1))
    fi
  done
}

# 1.1.22 Check Automounting is disabled
check_autofs(){
  echo
  echo "1.1.22 Disable Automounting"
  if [ ! -f $AUTOFS ]
  then
    echo_fail
  else
    disabled=`grep ^DISABLE_DIRECT $AUTOFS | cut -d"=" -f2`
    if [ "$disabled" == "1" ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi
}

# fix 1.1.22
fix_autofs(){
  echo
  echo "1.1.22 Disable Automounting"
  if [ ! -f $AUTOFS ]
  then
    echo "DISABLE_DIRECT=1" >$AUTOFS
    echo_pass
  else
    disabled=`grep ^DISABLE_DIRECT $AUTOFS | cut -d"=" -f2`
    if [ "$disabled" == "1" ]
    then
      echo_pass
    else
      sed -i "/DISABLE_DIRECT/s/0/1/" $AUTOFS
      echo_pass
    fi
  fi
}

# 1.2.2 Ensure gpgcheck is globally activated
# Fix: Edit /etc/yum.conf and set ' gpgcheck=1 ' in the [main] section.
#    Edit any failing files in /etc/yum.repos.d/* and set all instances of gpgcheck to '     1 '.
    
check_gpgcheck() {
  echo
  echo "1.2.2 Ensure gpgcheck in yum repos configuration and globally is activated"
  i=1
  for file in ${YUM_CONF} `find ${YUM_REPOS_DIR} -type f`
  do
      echo
      echo "1.2.3.${i} Ensure gpgcheck is activated in ${file}"
      if [ `egrep -c "^gpgcheck=0" ${file}` -gt 0 ] || [ `egrep -c "^gpgcheck" ${file}` == 0 ]
      then
        echo_fail
        if [ "${1}" == "1" ]
        then
          sed -i "/gpgcheck/s/0/1/" ${YUM_CONF}
        fi
      else
        if [ `egrep -c "^gpgcheck=1" ${file}` -gt 0 ]
        then
          echo_pass
        else
          echo_other "Something is wrong with gpgcheck configuration. It needs manual check."
        fi
      fi
      i=$((${i}+1))
      
  done
}

# 1.3.2 Ensure filesystem integrity is regularly checked
check_autofsck(){
  echo
  echo "1.3.2 Ensure filesystem integrity is regularly checked"
  if [ ! -f $AUTOFSCK ]
  then
    echo_fail
  else
    enabled=`grep ^AUTOFSCK_DEF_CHECK $AUTOFSCK | cut -d"=" -f2`
    if [ "$enabled" == "yes" ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi
}

# fix 1.3.2
fix_autofsck(){
  echo
  echo "1.3.2 Ensure filesystem integrity is regularly checked"
  if [ ! -f $AUTOFSCK ]
  then
    echo "AUTOFSCK_DEF_CHECK=yes" >$AUTOFSCK
    echo_pass
  else
    enabled=`grep ^AUTOFSCK_DEF_CHECK $AUTOFSCK | cut -d"=" -f2`
    if [ "$enabled" == "yes" ]
    then
      echo_pass
    else
      sed -i "/AUTOFSCK_DEF_CHECK/s/no/yes/" $AUTOFSCK
      echo_pass
    fi
  fi
}

# 1.4.1 Ensure permissions on bootloader config are configured
#   Fix: Run the following commands to set permissions on your grub configuration:
# chown root:root /boot/grub2/grub.cfg
# chmod og-rwx /boot/grub2/grub.cfg
check_grub() {
    echo
    echo "1.4.1 Ensure permissions on bootloader config are configured"
    if [ ${RHL7} -eq 1 ]; then
        GRUB_CONF=/boot/grub2/grub.cfg
    else
        GRUB_CONF=/boot/grub/grub.conf
    fi
    
    if [ $(stat -c %U-%G ${GRUB_CONF}) == "root-root" ] && [ $(stat -c %A ${GRUB_CONF}) == "-rw-------" ]; then
        echo_pass
    else
        echo_fail
        if [ "${1}" == "1" ]; then
            chown root:root ${GRUB_CONF}
            chmod og-rwx ${GRUB_CONF}
        fi
    fi
}

# 1.4.3 Ensure authentication required for single user mode
check_authreq(){
  echo
  echo "1.4.3 Ensure authentication required for single user mode"  
  if [ "${RHL7}" -gt 0 ]; then 
    for file in /usr/lib/systemd/system/emergency.service /usr/lib/systemd/system/rescue.service; do
      enabled=$(egrep "ExecStart.*sulogin" ${file} | grep -o sulogin)
      [ "$enabled" == "sulogin" ] || { 
        if [ "${1}" == "1" ]; then 
          sed -i "/ExecStart/s/sushell/sulogin/" $SYSCONFIGINIT
        else
          echo $file && echo_fail && exit 1
        fi; 
       }
    done
  else
    enabled=$(basename $(grep ^SINGLE $SYSCONFIGINIT | cut -d"=" -f2))
  fi
  
  if [ "$enabled" == "sulogin" ]
  then
    echo_pass
  else
    echo_fail
    if [ "${RHL6}" -gt 0 ]; then
      sed -i "/SINGLE/s/sushell/sulogin/" $SYSCONFIGINIT
    fi
    
  fi
}


# RHEL6:
# 1.4.3 Ensure authentication required for single user mode
#   Edit /etc/sysconfig/init and set SINGLE to ' /sbin/sulogin ':
#   SINGLE=/sbin/sulogin

# fix 1.4.3
fix_authreq(){
  echo
  echo "1.4.3 Ensure authentication required for single user mode"
  enabled=$(basename `grep ^SINGLE $SYSCONFIGINIT | cut -d"=" -f2`)
  if [ "$enabled" == "sulogin" ]
  then
    echo_pass
  else
    sed -i "/SINGLE/s/sushell/sulogin/" $SYSCONFIGINIT
    echo_pass
  fi
}

# 1.4.4 Ensure interactive boot is not enabled
check_interactiveboot(){
  echo
  echo "1.4.4 Ensure interactive boot is not enabled"
  enabled=`grep ^PROMPT $SYSCONFIGINIT | cut -d"=" -f2`
  if [ "$enabled" == "no" ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 1.4.4
fix_interactiveboot(){
  echo
  echo "1.4.4 Ensure interactive boot is not enabled"
  enabled=`grep ^PROMPT $SYSCONFIGINIT | cut -d"=" -f2`
  if [ "$enabled" == "no" ]
  then
    echo_pass
  else
    sed -i "/PROMPT/s/yes/no/" $SYSCONFIGINIT
    echo_pass
  fi
}

# 1.5.1 Ensure core dumps are restricted
check_coredumps(){
  echo
  echo "1.5.1 Ensure core dumps are restricted"
  # Check in /etc/security/limits.conf
  limits=`grep ^\* $LIMITSCONF | awk '{print $2$3$4}'`
  if [ "$limits" == "hardcore0" ]
  then
    limits=ok
  else
    limits=no
  fi
  # Check in /etc/sysctl.conf
  fssuid=`grep "fs.suid_dumpable" $SYSCTL | awk '{print $NF}'`
  if [[ "$limits" == "ok" && $fssuid -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi    
}

# Fix 1.5.1
fix_coredumps(){
  echo
  echo "1.5.1 Ensure core dumps are restricted"
  # Check in /etc/security/limits.conf
  limits=`grep ^\* $LIMITSCONF | awk '{print $2$3$4}'`
  if [ "$limits" == "hardcore0" ]
  then
    limits=ok
  else
    # Fixing /etc/security/limits.conf
    echo "* hard core 0" >> $LIMITSCONF
    limits=ok
  fi
  # Check in /etc/sysctl.conf
  fssuid=`grep "fs.suid_dumpable" $SYSCTL | awk '{print $NF}'`
  if [[ "$limits" == "ok" && $fssuid -eq 0 ]]
  then
    echo_pass
  else
    # Fixing /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> $SYSCTL
    echo_pass
  fi
}

# 1.5.4 Ensure prelink is disabled
check_prelink(){
  echo
  echo "1.5.4 Ensure prelink is disabled"
  if [ ! -f $PRELINK ]
  then
    echo_fail
  else
    disabled=`grep ^PRELINKING $PRELINK | cut -d"=" -f2`
    if [ "$disabled" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi
}

# Fix 1.5.4
fix_prelink(){
  echo
  echo "1.5.4 Ensure prelink is disabled"
  if [ ! -f $PRELINK ]
  then
    echo "PRELINKING=no" >$PRELINK
    echo_pass
  else
    disabled=`grep ^PRELINKING $PRELINK | cut -d"=" -f2`
    if [ "$disabled" == "no" ]
    then
      echo_pass
    elif [ "$disabled" == "" ]
    then
      # Adding the line to /etc/sysconfig/prelink file
      echo "PRELINKING=no" >> $PRELINK
      echo_pass
    else
      # Changing the value of PRELINKING
      sed -i 's/PRELINKING.*/PRELINKING=no/' $PRELINK
      echo_pass
    fi
  fi
}

# 1.7.2 Ensure GDM login banner is configured (this is missing from script)
# The fix: Create the /etc/dconf/profile/gdm file with the following contents:
# user-db:user
# system-db:gdm
# file-db:/usr/share/gdm/greeter-dconf-defaults
check_gdm(){
    echo -e "\n1.7.2 Ensure GDM login banner is configured"
    GDM_PROFILE=/etc/dconf/profile/gdm
    if [ -f ${GDM_PROFILE} ] && [ "$(grep -E "^user-db:user$" ${GDM_PROFILE})" = "user-db:user" ] && [ "$(grep -E "^system-db:gdm$" ${GDM_PROFILE})" == "system-db:gdm" ] && [ "$(grep -E "^file-db:/usr/share/gdm/greeter-dconf-defaults$" ${GDM_PROFILE})" == "file-db:/usr/share/gdm/greeter-dconf-defaults" ]; then
        echo_pass
    else
        echo_fail
        # TODO: Next dir structure is not existing in CentOS installed from minimal ISO, must be checked on RHL
        [ "${1}" == "1" ] && echo -e "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults" > ${GDM_PROFILE} && echo -e "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'" > /etc/dconf/db/gdm.d/01-banner-message
    fi
}

# 2.1.11 Ensure xinetd is not enabled
check_xinetd(){
  echo
  echo "2.1.11 Ensure xinetd is not enabled"
  installed=`rpm -q xinetd`
  if [ $? -eq 1 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 2.1.11
fix_xinetd(){
  echo
  echo "2.1.11 Ensure xinetd is not enabled"
  installed=`rpm -q xinetd`
  if [ $? -eq 1 ]
  then
    echo_pass
  else
    # Disable xinetd
    #chkconfig xinetd off
    # Delete xinetd package
    rpm -e xinetd
    echo_pass
  fi
}

 #~ TODO: 2.2.1.2 Ensure ntp is configured 
    #~ Fix: Add or edit restrict lines in /etc/ntp.conf to match the following:
    #~ restrict -4 default kod nomodify notrap nopeer noquery
    #~ restrict -6 default kod nomodify notrap nopeer noquery

    #~ Add or edit server lines to /etc/ntp.conf as appropriate:
    #~ server <remote-server>

    #~ Add or edit the OPTIONS in /etc/sysconfig/ntpd to include ' -u ntp:ntp ':   
    #~ OPTIONS="-u ntp:ntp"
    
#~ 2.2.2 Ensure X Window System is not installed
    #~ Fix: yum remove xorg-x11*
check_xorg(){
    echo -e "\n2.2.2 Ensure X Window System is not installed" 
    if [[ $(rpm -qa | grep -c xorg-x11) -gt 0 ]]; then
        echo_fail
        if [[ "${1}" -eq 1 ]]; then 
            yum remove -y xorg-x11*
        fi
    else 
        echo_pass
    fi
}

# 2.2.4 Ensure CUPS is not enabled
check_cups(){
  echo
  echo "2.2.4 Ensure CUPS is not enabled"
  rpm -q cups >/dev/null 2>&1
  if [ $? -eq 1 ]
  then
    # Means CUPS is not installed
    echo_pass
  else
    # Check if cups service is stopped
    service cups status | grep stop >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi
}

# Fix 2.2.4
fix_cups(){
  echo
  echo "2.2.4 Ensure CUPS is not enabled"
  rpm -q cups >/dev/null 2>&1
  if [ $? -eq 1 ]
  then
    # Means CUPS is not installed
    echo_pass
  else
    # Check if cups service is stopped
    service cups status | grep stop >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      # Stopping cups service
      service cups stop >/dev/null 2>&1
      chkconfig cups off
      echo_pass
    fi
  fi
}

# 2.2.7 Ensure NFS and RPC are not enabled
check_nfsandrpc(){
  echo
  echo "2.2.7 Ensure NFS and RPC are not enabled"
  rpm -q nfs-utils >/dev/null 2>&1
  if [ $? -eq 1 ]
  then
    # Means nfs-utils package is not installed
    echo_pass
  else
    # Check if services are enabled
    stop=`service nfs status | grep -c stop` 
    if [ $stop -le 1 ]
    then
      # Means not all services are stopped
      echo_fail
    elif [ $stop -eq 3 ]
      then
      echo_pass
    fi
  fi
}

# Fix 2.2.7
fix_nfsandrpc(){
  echo
  echo "2.2.7 Ensure NFS and RPC are not enabled"
  rpm -q nfs-utils >/dev/null 2>&1
  if [ $? -eq 1 ]
  then
    # Means nfs-utils package is not installed
    echo_pass
  else
    # Check if services are enabled
    stop=`service nfs status | grep -c stop`
    if [ $stop -le 1 ]
    then
      service nfs stop >/dev/null 2>&1
      service rpcbind stop >/dev/null 2>&1
      chkconfig nfs off
      chkconfig rpcbind off
      echo_pass
    elif [ $stop -eq 3 ]
      then
      echo_pass
    fi
  fi
}

# Check installed clients
check_clients(){
  echo
  echo "2.3.1 Ensure NIS Client is not installed"
  rpm -q yp-tools ypbind >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo_fail
  else
    echo_pass
  fi
  i=2
  for cl in rsh talk telnet
  do
    echo
    echo "2.3.$i Ensure $cl is not installed"
    rpm -q $cl >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo_fail
      i=$(($i+1))
    else
      echo_pass
      i=$(($i+1))
    fi
  done
  echo
  echo "2.3.5 Ensure LDAP client is not installed"
  rpm -q openldap-clients >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo_fail
  else
    echo_pass
  fi
}

# Fix installled clients
fix_clients(){
  echo
  echo "2.3.1 Ensure NIS Client is not installed"
  rpm -q yp-tools ypbind >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    rpm -e yp-tools ypbind >/dev/null 2>&1
    echo_pass
  else
    echo_pass
  fi
  i=2 
  for cl in rsh talk telnet
  do
    echo
    echo "2.3.$i Ensure $cl is not installed"
    rpm -q $cl >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      rpm -e $cl >/dev/null 2>&1
      echo_pass
      i=$(($i+1))
    else
      echo_pass
      i=$(($i+1))
    fi
  done
  echo
#  echo "2.3.5 Ensure LDAP client is not installed"
#  rpm -q openldap-clients >/dev/null 2>&1
#  if [ $? -eq 0 ]
#  then
#    rpm -e openldap-clients >/dev/null 2>&1
#    echo_pass
#  else
#    echo_pass
#  fi
}

# 3.1.2 Ensure packet redirect sending is disabled
check_packetredir(){
  echo
  echo "3.1.2 Ensure packet redirect sending is disabled"
  val1=`sysctl -n net.ipv4.conf.all.send_redirects`
  val2=`sysctl -n net.ipv4.conf.default.send_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.1.2
fix_packetredir(){
  echo
  echo "3.1.2 Ensure packet redirect sending is disabled"
  val1=`sysctl -n net.ipv4.conf.all.send_redirects`
  val2=`sysctl -n net.ipv4.conf.default.send_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv4.conf.$v.send_redirects $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv4.conf.$v.send_redirects = 0" >> $SYSCTL
      else
        sed -i /^net.ipv4.conf.$v.send_redirects/s/1/0/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.2.2 Ensure ICMP redirects are not accepted
check_icmpredir(){
  echo
  echo "3.2.2 Ensure ICMP redirects are not accepted"
  val1=`sysctl -n net.ipv4.conf.all.accept_redirects`
  val2=`sysctl -n net.ipv4.conf.default.accept_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.2.2
fix_icmpredir(){
  echo
  echo "3.2.2 Ensure ICMP redirects are not accepted"
  val1=`sysctl -n net.ipv4.conf.all.accept_redirects`
  val2=`sysctl -n net.ipv4.conf.default.accept_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv4.conf.$v.accept_redirects $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv4.conf.$v.accept_redirects = 0" >> $SYSCTL
      else
        sed -i /^net.ipv4.conf.$v.accept_redirects/s/1/0/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.2.3 Ensure secure ICMP redirects are not accepted
check_secicmpredir(){
  echo
  echo "3.2.2 Ensure secure ICMP redirects are not accepted"
  val1=`sysctl -n net.ipv4.conf.all.secure_redirects`
  val2=`sysctl -n net.ipv4.conf.default.secure_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.2.2
fix_secicmpredir(){
  echo
  echo "3.2.2 Ensure secure ICMP redirects are not accepted"
  val1=`sysctl -n net.ipv4.conf.all.secure_redirects`
  val2=`sysctl -n net.ipv4.conf.default.secure_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv4.conf.all.secure_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.secure_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv4.conf.$v.secure_redirects $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv4.conf.$v.secure_redirects = 0" >> $SYSCTL
      else
        sed -i /^net.ipv4.conf.$v.secure_redirects/s/1/0/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.2.4 Ensure suspicious packets are logged
check_logsusppkt(){
  echo
  echo "3.2.4 Ensure suspicious packets are logged"
  val1=`sysctl -n net.ipv4.conf.all.log_martians`
  val2=`sysctl -n net.ipv4.conf.default.log_martians`
  if [[ $val1 -eq 1 && $val2 -eq 1 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.2.4
fix_logsusppkt(){
echo
  echo "3.2.4 Ensure suspicious packets are logged"
  val1=`sysctl -n net.ipv4.conf.all.log_martians`
  val2=`sysctl -n net.ipv4.conf.default.log_martians`
  if [[ $val1 -eq 1 && $val2 -eq 1 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv4.conf.$v.log_martians $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv4.conf.$v.log_martians = 1" >> $SYSCTL
      else
        sed -i /^net.ipv4.conf.$v.log_martians/s/0/1/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.2.7 Ensure Reverse Path Filtering is enabled
check_rpfilter(){
  echo
  echo "3.2.7 Ensure Reverse Path Filtering is enabled"
  val1=`sysctl -n net.ipv4.conf.all.rp_filter`
  val2=`sysctl -n net.ipv4.conf.default.rp_filter`
  if [[ $val1 -eq 1 && $val2 -eq 1 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.2.7
fix_rpfilter(){
  echo
  echo "3.2.7 Ensure Reverse Path Filtering is enabled"
  val1=`sysctl -n net.ipv4.conf.all.rp_filter`
  val2=`sysctl -n net.ipv4.conf.default.rp_filter`
  if [[ $val1 -eq 1 && $val2 -eq 1 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv4.conf.$v.rp_filter $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv4.conf.$v.rp_filter = 1" >> $SYSCTL
      else
        sed -i /^net.ipv4.conf.$v.rp_filter/s/0/1/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.3.1 Ensure IPv6 router advertisements are not accepted
check_acceptra(){
  echo
  echo "3.3.1 Ensure IPv6 router advertisements are not accepted"
  val1=`sysctl -n net.ipv6.conf.all.accept_ra`
  val2=`sysctl -n net.ipv6.conf.default.accept_ra`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.3.1
fix_acceptra(){
  echo
  echo "3.3.1 Ensure IPv6 router advertisements are not accepted"
  val1=`sysctl -n net.ipv6.conf.all.accept_ra`
  val2=`sysctl -n net.ipv6.conf.default.accept_ra`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.accept_ra=0 >/dev/null 2>&1
    sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv6.conf.$v.accept_ra $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv6.conf.$v.accept_ra = 0" >> $SYSCTL
      else
        sed -i /^net.ipv6.conf.$v.accept_ra/s/1/0/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.3.2 Ensure IPv6 redirects are not accepted
check_ipv6redir(){
  echo
  echo "3.3.2 Ensure IPv6 redirects are not accepted"
  val1=`sysctl -n net.ipv6.conf.all.accept_redirects`
  val2=`sysctl -n net.ipv6.conf.default.accept_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.3.2
fix_ipv6redir(){
  echo
  echo "3.3.2 Ensure IPv6 redirects are not accepted"
  val1=`sysctl -n net.ipv6.conf.all.accept_redirects`
  val2=`sysctl -n net.ipv6.conf.default.accept_redirects`
  if [[ $val1 -eq 0 && $val2 -eq 0 ]]
  then
    echo_pass
  else
    sysctl -w net.ipv6.conf.all.accept_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.accept_redirects=0 >/dev/null 2>&1
    sysctl -w net.ipv6.route.flush=1 >/dev/null 2>&1
    for v in all default
    do
      grep -q ^net.ipv6.conf.$v.accept_redirects $SYSCTL
      if [ $? -eq 1 ]
      then
        echo "net.ipv6.conf.$v.accept_redirects = 0" >> $SYSCTL
      else
        sed -i /^net.ipv6.conf.$v.accept_redirects/s/1/0/ $SYSCTL
      fi
    done
    echo_pass
  fi
}

# 3.4.3 Ensure /etc/hosts.deny is configured
check_hostsdeny(){
  echo
  echo "3.4.3 Ensure /etc/hosts.deny is configured"
  if [ -f $HOSTSDENY ]
  then
    grep -q ^ALL $HOSTSDENY
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 3.4.3
fix_hostsdeny(){
  echo
  echo "3.4.3 Ensure /etc/hosts.deny is configured"
  if [ -f $HOSTSDENY ]
  then
    grep -q ^"ALL: ALL" $HOSTSDENY
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo "ALL: ALL" >>$HOSTSDENY
      echo_pass
    fi
  else
    cat >$HOSTSDENY<<EOF
#
# hosts.deny    This file describes the names of the hosts which are
#               *not* allowed to use the local INET services, as decided
#               by the '/usr/sbin/tcpd' server.
#
ALL: ALL
EOF
    echo_pass
  fi
}

# 3.6.2 Ensure default deny firewall policy
check_fwdenypolicy(){
  echo
  echo "3.6.2 Ensure default deny firewall policy"
  iptables -L INPUT | grep -i reject >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    iptables -L FORWARD | grep -i reject >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi
}

# Fix 3.6.2
fix_fwdenypolicy(){
  echo
  echo "3.6.2 Ensure default deny firewall policy"
  iptables -L INPUT | grep -i reject >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    iptables -L FORWARD | grep -i reject >/dev/null 2>&1
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      cat >$IPTABLES<<EOF
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
      echo_pass
    fi
  else
    cat >$IPTABLES<<EOF
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
  fi
}

# 3.6.3 Ensure loopback traffic is configured
check_lotraffic(){
  echo
  echo "3.6.3 Ensure loopback traffic is configured"
  iptables -S INPUT | grep -i "lo -j ACCEPT"  >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 3.6.3
fix_lotraffic(){
  echo
  echo "3.6.3 Ensure loopback traffic is configured"
  iptables -S INPUT | grep -i "lo -j ACCEPT"  >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    cat >$IPTABLES<<EOF
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
EOF
    echo_pass
  fi
}

# 4.2.1.3 Ensure rsyslog default file permissions configured
check_rsyslogfp(){
  echo
  echo "4.2.1.3 Ensure rsyslog default file permissions configured"
  grep -q '^$FileCreateMode' $RSYSLOG
  if [ $? -eq 0 ]
  then
    val=`grep '^$FileCreateMode' $RSYSLOG | awk '{print $NF}'`
    if [ $val -eq 0600 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 4.2.1.3
fix_rsyslogfp(){
  echo
  echo "4.2.1.3 Ensure rsyslog default file permissions configured"
  grep -q '^$FileCreateMode' $RSYSLOG
  if [ $? -eq 0 ]
  then
    val=`grep '^$FileCreateMode' $RSYSLOG | awk '{print $NF}'`
    if [ $val -eq 0600 ]
    then
      echo_pass
    else
      sed -i s/'^$FileCreateMode.*'/'$FileCreateMode 0600'/ $RSYSLOG
      echo_pass
    fi
  else
    echo '$FileCreateMode 0600' >>$RSYSLOG
    echo_pass
  fi
}

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host
check_rsyslogrh(){
  echo
  echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
  grep -q "@rloghost" $RSYSLOG
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 4.2.1.4
fix_rsyslogrh(){
  echo
  echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
  grep -q "@rloghost" $RSYSLOG
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    ed $RSYSLOG <<END >/dev/null 2>&1
/mail.none;authpriv.none;cron.none/
a
*.err;mail.none;authpriv.none;cron.none                 @rloghost
.
/local7/
a
local7.*                                                @rloghost
.
w
q
END
    echo_pass
  fi
}

# 4.2.4 Ensure permissions on all logfiles are configured
check_logperms(){
  echo
  echo "4.2.4 Ensure permissions on all logfiles are configured"
  c=0
  for f in messages secure maillog cron spooler boot.log
  do
    if [ -f $VARLOG/$f ]
    then
      perms=`ls -l $VARLOG/$f | cut -d"." -f1`
      own=`ls -l $VARLOG/$f | cut -d" " -f3`
      grp=`ls -l $VARLOG/$f | cut -d" " -f4`
      if [[ "$perms" == "-rw-------" && "$own" == "root" && "$grp" == "root" ]]
      then
        c=$(($c+1))
      fi
    fi
  done
  if [ $c -eq 6 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 4.2.4
fix_logperms(){
  echo
  echo "4.2.4 Ensure permissions on all logfiles are configured"
  c=0
  for f in messages secure maillog cron spooler boot.log
  do
    if [ -f $VARLOG/$f ]
    then
      perms=`ls -l $VARLOG/$f | cut -d"." -f1`
      own=`ls -l $VARLOG/$f | cut -d" " -f3`
      grp=`ls -l $VARLOG/$f | cut -d" " -f4`
      if [[ ! "$perms" == "-rw-------" || ! "$own" == "root" || ! "$grp" == "root" ]]
      then
        chmod 600 $VARLOG/$f
        chown root:root $VARLOG/$f
        c=$(($c+1))
      fi
    else
      touch $VARLOG/$f
      chmod 600 $VARLOG/$f
      chown root:root $VARLOG/$f
      c=$(($c+1))
    fi
  done
  if [ $c -eq 6 ]
  then
    echo_pass
  fi
}

# Ensure permissions of crontab files
check_cronfiles(){
  cronfiles=([0]="/etc/crontab" [1]="/etc/cron.hourly" [2]="/etc/cron.daily" [3]="/etc/cron.weekly" [4]="/etc/cron.monthly" [5]="/etc/cron.d")
  i=2
  for f in ${cronfiles[@]}
  do
    echo
    echo "5.1.$i Ensure permissions on $f are configured"
    if [[ -f $f || -d $f ]]
    then
      perms=`ls -ld $f | cut -d"." -f1 | tail -c 7`
      own=`ls -ld $f | cut -d" " -f3`
      grp=`ls -ld $f | cut -d" " -f4`
      if [[ "$perms" == "------" && "$own" == "root" && "$grp" == "root" ]]
      then
        echo_pass
        i=$(($i+1))
      else
        echo_fail
        i=$(($i+1))
      fi
    else
      echo_fail
      i=$(($i+1))
    fi
  done
}

# Fix permissions in conrt files
fix_cronfiles(){
  cronfiles=([0]="/etc/crontab" [1]="/etc/cron.hourly" [2]="/etc/cron.daily" [3]="/etc/cron.weekly" [4]="/etc/cron.monthly" [5]="/etc/cron.d")
  i=2
  for f in ${cronfiles[@]}
  do
    echo
    echo "5.1.$i Ensure permissions on $f are configured"
    if [[ -f $f || -d $f ]]
    then
      perms=`ls -ld $f | cut -d"." -f1 | tail -c 7`
      own=`ls -ld $f | cut -d" " -f3`
      grp=`ls -ld $f | cut -d" " -f4`
      if [[ "$perms" == "------" && "$own" == "root" && "$grp" == "root" ]]
      then
        echo_pass
        i=$(($i+1))
      else
        chown root:root $f
        chmod og-rwx $f
        echo_pass
        i=$(($i+1))
      fi
    else
      touch $f
      chown root:root $f
      chmod og-rwx $f
      echo_pass
      i=$(($i+1))
    fi
  done
}

# 5.1.8 Ensure at/cron is restricted to authorized users
check_cronatusrs(){
  echo
  echo "5.1.8 Ensure at/cron is restricted to authorized users"
  if [[ -f /etc/at.deny && -f /etc/cron.deny ]]
  then
    echo_fail
  elif [[ -f /etc/at.allow && -f /etc/cron.allow ]]
  then
    c=0
    for f in at cron
    do
      perms=`ls -l /etc/$f.allow | cut -d"." -f1 | tail -c 7`
      own=`ls -l /etc/$f.allow | cut -d" " -f3`
      grp=`ls -l /etc/$f.allow | cut -d" " -f4`
      if [[ "$perms" == "------" && "$own" == "root" && "$grp" == "root" ]]
      then
        c=$(($c+1))
      fi
    done
    if [ $c -eq 2 ]
    then
      echo_pass
    else
      echo_fail
    fi
  fi  
}

# Fix 5.1.8
fix_cronatusrs(){
  echo
  echo "5.1.8 Ensure at/cron is restricted to authorized users"
  if [[ -f /etc/at.deny && -f /etc/cron.deny ]]
  then
    rm -f /etc/at.deny /etc/cron.deny
    touch /etc/at.allow /etc/cron.allow
    chown root:root /etc/at.allow /etc/cron.allow
    chmod og-rwx /etc/at.allow /etc/cron.allow
    echo_pass
  elif [[ -f /etc/at.allow && -f /etc/cron.allow ]]
  then
    c=0
    for f in at cron
    do
      perms=`ls -l /etc/$f.allow | cut -d"." -f1 | tail -c 7`
      own=`ls -l /etc/$f.allow | cut -d" " -f3`
      grp=`ls -l /etc/$f.allow | cut -d" " -f4`
      if [[ "$perms" == "------" && "$own" == "root" && "$grp" == "root" ]]
      then
        c=$(($c+1))
      fi
    done
    if [ $c -eq 2 ]
    then
      echo_pass
    else
      chown root:root /etc/at.allow /etc/cron.allow
      chmod og-rwx /etc/at.allow /etc/cron.allow
      echo_pass
    fi
  else
    touch /etc/at.allow /etc/cron.allow
    chown root:root /etc/at.allow /etc/cron.allow
    chmod og-rwx /etc/at.allow /etc/cron.allow
    echo_pass
  fi
}

#~ 5.2.2 Ensure SSH Protocol is set to 2
    #~ Fix: Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    #~ Protocol 2
check_ssh_protocol() {
    echo -e "\n5.2.2 Ensure SSH Protocol is set to 2"
    if [[ $(grep -cP "^Protocol.*2" ${SSHCONFIG}) -gt 0 ]]; then
        echo_pass
    else
        echo_fail
        if [[ "${1}" -eq 1 ]]; then
            sed -i "/Protocol/s/1/2/" ${SSHCONFIG}
        fi
    fi
}


# 5.2.3 Ensure SSH LogLevel is set to INFO
check_sshloglevel(){
  echo
  echo "5.2.3 Ensure SSH LogLevel is set to INFO"
  grep -q ^LogLevel $SSHCONFIG
  if [ $? -eq 0 ]
  then
    loglevel=`grep ^LogLevel $SSHCONFIG | awk '{print $NF}'`
    if [ "$loglevel" == "INFO" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi 
}

# Fix 5.2.3
fix_sshloglevel(){
  echo
  echo "5.2.3 Ensure SSH LogLevel is set to INFO"
  grep -q ^LogLevel $SSHCONFIG
  if [ $? -eq 0 ]
  then
    loglevel=`grep ^LogLevel $SSHCONFIG | awk '{print $NF}'`
    if [ "$loglevel" == "INFO" ]
    then
      echo_pass
    else
      sed -i s/"^LogLevel.*"/"LogLevel INFO"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "LogLevel INFO" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.4 Ensure SSH X11 forwarding is disabled
check_sshx11forward(){
  echo
  echo "5.2.4 Ensure SSH X11 forwarding is disabled"
  grep -q ^X11Forwarding $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^X11Forwarding $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.4
fix_sshx11forward(){
  echo
  echo "5.2.4 Ensure SSH X11 forwarding is disabled"
  grep -q ^X11Forwarding $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^X11Forwarding $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      sed -i s/"^X11Forwarding.*"/"X11Forwarding no"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "X11Forwarding no" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
check_sshmaxauth(){
  echo
  echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
  grep -q ^MaxAuthTries $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^MaxAuthTries $SSHCONFIG | awk '{print $NF}'`
    if [ $val -le 4 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.5
fix_sshmaxauth(){
  echo
  echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
  grep -q ^MaxAuthTries $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^MaxAuthTries $SSHCONFIG | awk '{print $NF}'`
    if [ $val -le 4 ]
    then
      echo_pass
    else
      sed -i s/"^MaxAuthTries.*"/"MaxAuthTries 4"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "MaxAuthTries 4" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.6 Ensure SSH IgnoreRhosts is enabled
check_sshignorerhosts(){
  echo
  echo "5.2.6 Ensure SSH IgnoreRhosts is enabled"
  grep -q ^IgnoreRhosts $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^IgnoreRhosts $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "yes" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.6
fix_sshignorerhosts(){
  echo
  echo "5.2.6 Ensure SSH IgnoreRhosts is enabled"
  grep -q ^IgnoreRhosts $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^IgnoreRhosts $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "yes" ]
    then
      echo_pass
    else
      sed -i s/"^IgnoreRhosts.*"/"IgnoreRhosts yes"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "IgnoreRhosts yes" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.7 Ensure SSH HostbasedAuthentication is disabled
check_sshhostbasedauth(){
  echo
  echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
  grep -q ^HostbasedAuthentication $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^HostbasedAuthentication $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.7
fix_sshhostbasedauth(){
  echo
  echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
  grep -q ^HostbasedAuthentication $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^HostbasedAuthentication $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      sed -i s/"^HostbasedAuthentication.*"/"HostbasedAuthentication no"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "HostbasedAuthentication no" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.8 Ensure SSH root login is disabled
check_sshrootlogin(){
  echo
  echo "5.2.8 Ensure SSH root login is disabled"
  grep -q ^PermitRootLogin $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitRootLogin $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.8
fix_sshrootlogin(){
  echo
  echo "5.2.8 Ensure SSH root login is disabled"
  grep -q ^PermitRootLogin $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitRootLogin $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      sed -i s/"^PermitRootLogin.*"/"PermitRootLogin no"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "PermitRootLogin no" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled
check_sshpermitemptypwd(){
  echo
  echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
  grep -q ^PermitEmptyPasswords $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitEmptyPasswords $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.9
fix_sshpermitemptypwd(){
  echo
  echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
  grep -q ^PermitEmptyPasswords $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitEmptyPasswords $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      sed -i s/"^PermitEmptyPasswords.*"/"PermitEmptyPasswords no"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "PermitEmptyPasswords no" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled
check_sshpermuserenv(){
  echo
  echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
  grep -q ^PermitUserEnvironment $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitUserEnvironment $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.10
fix_sshpermuserenv(){
  echo
  echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
  grep -q ^PermitUserEnvironment $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^PermitUserEnvironment $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "no" ]
    then
      echo_pass
    else
      sed -i s/"^PermitUserEnvironment.*"/"PermitUserEnvironment no"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "PermitUserEnvironment no" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.11 Ensure only approved ciphers are used
check_sshciphers(){
  echo
  echo "5.2.11 Ensure only approved ciphers are used"
  grep -q ^Ciphers $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^Ciphers $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "aes128-ctr,aes192-ctr,aes256-ctr" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.11
fix_sshciphers(){
  echo
  echo "5.2.11 Ensure only approved ciphers are used"
  grep -q ^Ciphers $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^Ciphers $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "aes128-ctr,aes192-ctr,aes256-ctr" ]
    then
      echo_pass
    else
      sed -i s/"^Ciphers.*"/"Ciphers aes128-ctr,aes192-ctr,aes256-ctr"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.12 Ensure only approved MAC algorithms are used
check_sshmacalgo(){
  echo
  echo "5.2.12 Ensure only approved MAC algorithms are used"
  grep -q ^MACs $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^MACs $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.12
fix_sshmacalgo(){
  echo
  echo "5.2.12 Ensure only approved MAC algorithms are used"
  grep -q ^MACs $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^MACs $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com" ]
    then
      echo_pass
    else
      sed -i s/"^MACs.*"/"MACs hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "MACs hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.13 Ensure SSH Idle Timeout Interval is configured
check_sshidletmout(){
  echo
  echo "5.2.13 Ensure SSH Idle Timeout Interval is configured"
  grep -q ^ClientAliveInterval $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^ClientAliveInterval $SSHCONFIG | awk '{print $NF}'`
    if [ $val -eq 300 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.13
fix_sshidletmout(){
  echo
  echo "5.2.13 Ensure SSH Idle Timeout Interval is configured"
  grep -q ^ClientAliveInterval $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^ClientAliveInterval $SSHCONFIG | awk '{print $NF}'`
    if [ $val -eq 300 ]
    then
      echo_pass
    else
      sed -i s/"^ClientAliveInterval.*"/"ClientAliveInterval 300"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "ClientAliveInterval 300" >>$SSHCONFIG
    echo_pass
  fi
}

# 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less
check_sshlogingrctm(){
  echo
  echo "5.2.14 Ensure SSH LoginGraceTime is set to one minute or less"
  grep -q ^LoginGraceTime $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^LoginGraceTime $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "60" ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.2.14
fix_sshlogingrctm(){
  echo
  echo "5.2.14 Ensure SSH LoginGraceTime is set to one minute or less"
  grep -q ^LoginGraceTime $SSHCONFIG
  if [ $? -eq 0 ]
  then
    val=`grep ^LoginGraceTime $SSHCONFIG | awk '{print $NF}'`
    if [ "$val" == "60" ]
    then
      echo_pass
    else
      sed -i s/"^LoginGraceTime.*"/"LoginGraceTime 60"/ $SSHCONFIG
      echo_pass
    fi
  else
    echo "LoginGraceTime 60" >>$SSHCONFIG
    echo_pass
  fi
}

#~ 5.2.15 Ensure SSH access is limited
    #~ Fix: Edit the /etc/ssh/sshd_config file to set one or more of the parameter as  follows:

    #~ AllowUsers <userlist>
    #~ AllowGroups <grouplist>
    #~ DenyUsers <userlist>
    #~ DenyGroups <grouplist>
#~ TODO: Change <userlist> and <grouplist> with appropriate lists
check_ssh_users() {
    echo -e "\n5.2.15 Ensure SSH access is limited"
    if [[ $(grep -cE "^AllowUsers <userlist>" ${SSHCONFIG}) -eq 1 ]] && \
       [[ $(grep -cE "^AllowGroups <grouplist>" ${SSHCONFIG}) -eq 1 ]] && \
       [[ $(grep -cE "^DenyUsers <userlist>" ${SSHCONFIG}) -eq 1 ]] && \
       [[ $(grep -cE "^DenyGroups <grouplist>" ${SSHCONFIG}) -eq 1 ]]; then
        echo_pass
    else
        echo_fail
        if [[ "${1}" -eq 1 ]]; then
            sed -i "/AllowUsers/s/.*/AllowUsers <userlist>/" ${SSHCONFIG}
            sed -i "/AllowGroups/s/.*/AllowGroups <grouplist>/" ${SSHCONFIG}
            sed -i "/DenyUsers/s/.*/DenyUsers <userlist>/" ${SSHCONFIG}
            sed -i "/DenyGroups/s/.*/DenyGroups <grouplist>/" ${SSHCONFIG}
        fi
    fi
    
}

# 5.3.1 Ensure password creation requirements are configured
check_pwdcreation(){
  echo
  echo "5.3.1 Ensure password creation requirements are configured"
  grep -q pam_passwdqc $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    grep -q pam_passwdqc $PASSWDAUTH
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.3.1
fix_pwdcreation(){
  echo
  echo "5.3.1 Ensure password creation requirements are configured"
  grep -q pam_passwdqc $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    grep -q pam_passwdqc $PASSWDAUTH
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      sed -i /pam_cracklib.so/s/"pam_cracklib.so.*"/"pam_passwdqc.so random=0 enforce=everyone min=disabled,disabled,disabled,disabled,13"/ $PASSWDAUTH
      sed -i /"pam_unix.so sha512"/s/try_first_pass/use_first_pass/ $PASSWDAUTH
      echo_pass
    fi
  else
    sed -i /pam_cracklib.so/s/"pam_cracklib.so.*"/"pam_passwdqc.so random=0 enforce=everyone min=disabled,disabled,disabled,disabled,13"/ $SYSTEMAUTH
    sed -i /"pam_unix.so sha512"/s/try_first_pass/use_first_pass/ $SYSTEMAUTH
    sed -i /pam_cracklib.so/s/"pam_cracklib.so.*"/"pam_passwdqc.so random=0 enforce=everyone min=disabled,disabled,disabled,disabled,13"/ $PASSWDAUTH  
    sed -i /"pam_unix.so sha512"/s/try_first_pass/use_first_pass/ $PASSWDAUTH
    echo_pass
  fi
}

# 5.3.2 Ensure lockout for failed password attempts is configured
check_faillock(){
  echo
  echo "5.3.2 Ensure lockout for failed password attempts is configured"
  grep -q pam_faillock $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    grep -q pam_faillock $PASSWDAUTH
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      echo_fail
    fi
  else
    echo_fail
  fi
}

# Fix 5.3.2
fix_faillock(){
  echo
  echo "5.3.2 Ensure lockout for failed password attempts is configured"
  grep -q pam_faillock $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    grep -q pam_faillock $PASSWDAUTH
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      ed $PASSWDAUTH <<END >/dev/null 2>&1
/pam_env.so/
a
auth        required      pam_faillock.so preauth audit silent deny=3 unlock_time=1200
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1200
auth        sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1200
.
w
q
END
      ed $PASSWDAUTH <<END >/dev/null 2>&1     
/pam_unix.so nullok try_first_pass/
d
d
.
w
q
END
      echo_pass
    fi
  else
    ed $SYSTEMAUTH <<END >/dev/null 2>&1
/pam_env.so/
a
auth        required      pam_faillock.so preauth audit silent deny=3 unlock_time=1200
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1200
auth        sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1200
.
w
q
END
    ed $SYSTEMAUTH <<END >/dev/null 2>&1
/pam_unix.so nullok try_first_pass/
d
d
.
w
q
END
    ed $PASSWDAUTH <<END >/dev/null 2>&1
/pam_env.so/
a
auth        required      pam_faillock.so preauth audit silent deny=3 unlock_time=1200
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1200
auth        sufficient    pam_faillock.so authsucc audit deny=3 unlock_time=1200
.
w
q
END
    ed $PASSWDAUTH <<END >/dev/null 2>&1
/pam_unix.so nullok try_first_pass/
d
d
.
w
q
END
    echo_pass
  fi
}

# 5.3.3 Ensure password reuse is limited
check_pwdreuse(){
  echo
  echo "5.3.3 Ensure password reuse is limited"
  grep -q "remember" $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 5.3.3
fix_pwdreuse(){
  echo
  echo "5.3.3 Ensure password reuse is limited"
  grep -q "remember" $SYSTEMAUTH
  if [ $? -eq 0 ]
  then
    echo_pass
  else
    sed -i /"password.*pam_unix.so"/s/$/" remember=10"/ $SYSTEMAUTH
    echo_pass
  fi
}

# 5.4.1.1 Ensure password expiration is 90 days or less
check_pwdexpiration(){
  echo
  echo "5.4.1.1 Ensure password expiration is 90 days or less"
  val=`grep ^PASS_MAX_DAYS $LOGINDEFS | awk '{print $NF}'`
  if [ $val -le 90 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 5.4.1.1
fix_pwdexpiration(){
  echo
  echo "5.4.1.1 Ensure password expiration is 90 days or less"
  val=`grep ^PASS_MAX_DAYS $LOGINDEFS | awk '{print $NF}'`
  if [ $val -le 90 ]
  then
    echo_pass
  else
    sed -i /^PASS_MAX_DAYS/s/"^PASS_MAX_DAYS.*"/"PASS_MAX_DAYS\t90"/ $LOGINDEFS
    echo_pass
  fi
}

# 5.4.1.2 Ensure minimum days between password changes is 7 or more
check_minpwdchng(){
  echo
  echo "5.4.1.2 Ensure minimum days between password changes is 7 or more"
  val=`grep ^PASS_MIN_DAYS $LOGINDEFS | awk '{print $NF}'`
  if [ $val -eq 7 ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 5.4.1.2
fix_minpwdchng(){
  echo
  echo "5.4.1.2 Ensure minimum days between password changes is 7 or more"
  val=`grep ^PASS_MIN_DAYS $LOGINDEFS | awk '{print $NF}'`
  if [ $val -eq 7 ]
  then
    echo_pass
  else
    sed -i /^PASS_MIN_DAYS/s/"^PASS_MIN_DAYS.*"/"PASS_MIN_DAYS\t7"/ $LOGINDEFS
    echo_pass
  fi
}

# 5.4.1.4 Ensure inactive password lock is 30 days or less
check_inactivepwdlock(){
  echo
  echo "5.4.1.4 Ensure inactive password lock is 30 days or less"
  val=`grep ^INACTIVE $DEFUSERADD | cut -d"=" -f2`
  if [ $val -eq 30 ]
  then
    echo_pass
  else
    echo_fail
  fi  
}

# Fix 5.4.1.4
fix_inactivepwdlock(){
  echo
  echo "5.4.1.4 Ensure inactive password lock is 30 days or less"
  val=`grep ^INACTIVE $DEFUSERADD | cut -d"=" -f2`
  if [ $val -eq 30 ]
  then
    echo_pass
  else
    sed -i s/"^INACTIVE.*"/"INACTIVE=30"/ $DEFUSERADD
    echo_pass
  fi
}

# 5.4.2 Ensure system accounts are non-login
check_sysacctnologin(){
  echo
  echo "5.4.2 Ensure system accounts are non-login"
  numsysacct=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print $1}' | wc -l`
  sysacct=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print $1}'`
  i=0
  for u in $sysacct
  do
    shell=`grep ^$u $PASSWD | cut -d":" -f7`
    if [ "$shell" == "/sbin/nologin" ]
    then
      i=$(($i+1))
    fi
  done
  if [ $i -eq $numsysacct ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 5.4.2
fix_sysacctnologin(){
  echo
  echo "5.4.2 Ensure system accounts are non-login"
  numsysacct=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print $1}' | wc -l`
  sysacct=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print $1}'`
  i=0
  for u in $sysacct
  do
    shell=`grep ^$u $PASSWD | cut -d":" -f7`
    if [ "$shell" == "/sbin/nologin" ]
    then
      i=$(($i+1))
    else
      usermod -s /sbin/nologin $u
      i=$(($i+1))
    fi
  done
  if [ $i -eq $numsysacct ]
  then
    echo_pass
  else
    for u in $sysacct
    do
      usermod -s /sbin/nologin $u
    done
    echo_pass
  fi
}

# 5.4.4 Ensure default user umask is 027 or more restrictive
check_umask(){
  echo
  echo "5.4.4 Ensure default user umask is 027 or more restrictive"
  val=`umask | awk '{print $NF}'`
  if [[ $val == 0027 || $val == 0077 ]]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 5.4.4
fix_umask(){
  echo
  echo "5.4.4 Ensure default user umask is 027 or more restrictive"
  val=`umask | awk '{print $NF}'`
  if [[ $val == 0027 || $val == 0077 ]]
  then
    echo_pass
  else
    for f in /etc/bashrc /etc/profile /etc/csh.cshrc
    do
      grep -q umask $f
      if [ $? -eq 0 ]
      then
        sed -i s/"umask.*"/"umask 027"/ $f
      else
        echo "umask 027" >>$f
     fi
    done
  fi
}

# 5.6 Ensure access to the su command is restricted
check_suaccess(){
  echo
  echo "5.6 Ensure access to the su command is restricted"
  val=`grep "required$pam_wheel" $PAMSU | awk '{print $1}'`
  if [ "$val" == "#auth" ]
  then
    echo_fail
  else
    echo_pass
  fi
}

# Fix 5.6
fix_suaccess(){
  echo
  echo "5.6 Ensure access to the su command is restricted"
  val=`grep "required$pam_wheel" $PAMSU | awk '{print $1}'`
  if [ "$val" == "#auth" ]
  then
    ed $PAMSU << END >/dev/null 2>&1
/required.*pam_wheel.so/
s/^#//
w
q
END
    echo_pass
  else
    echo_pass
  fi
}

# 6.1.3 Ensure permissions on /etc/shadow are configured
check_shadowperms(){
  echo
  echo "6.1.3 Ensure permissions on /etc/shadow are configured"
  perms=`ls -l $SHADOW | cut -d"." -f1`
  if [ "$perms" == "-----------" ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 6.1.3
fix_shadowperms(){
  echo
  echo "6.1.3 Ensure permissions on /etc/shadow are configured"
  perms=`ls -l $SHADOW | cut -d"." -f1`
  if [ "$perms" == "----------" ]
  then
    echo_pass
  else
    chmod 000 $SHADOW
    echo_pass
  fi
}

# 6.1.6 Ensure permissions on /etc/passwd- are configured
check_passwdperms(){
  echo
  echo "6.1.6 Ensure permissions on /etc/passwd- are configured"
  perms=`ls -l $PASSWD | cut -d"." -f1`
  if [ "$perms" == "-rw-r--r--" ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 6.1.6
fix_passwdperms(){
  echo
  echo "6.1.6 Ensure permissions on /etc/passwd- are configured"
  perms=`ls -l $PASSWD | cut -d"." -f1`
  if [ "$perms" == "-rw-r--r--" ]
  then
    echo_pass
  else
    chmod 644 $PASSWD
    echo_pass
  fi
}
#~ 6.1.8 Ensure permissions on /etc/group- are configured
    #~ Fix: Run the following command to set permissions on /etc/group- :

    #~ # chown root:root /etc/group-
    #~ # chmod 600 /etc/group-
check_group_() {
    echo -e "\n6.1.8 Ensure permissions on /etc/group- are configured"
    GROUP_=/etc/group-
    if [ $(stat -c %U-%G ${GROUP_}) == "root-root" ] && [ $(stat -c %a ${GROUP_}) == "600" ]; then
        echo_pass
    else
        echo_fail
        if [ "${1}" == "1" ]; then
            chown root:root ${GROUP_}
            chmod 600 ${GROUP_}
        fi
    fi
}

# 6.2.6 Ensure root PATH Integrity
check_rootpathint(){
  echo
  echo "6.2.6 Ensure root PATH Integrity"
  validpath="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"
  currpath=`echo $PATH`
  if [ "$validpath" == "$currpath" ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 6.2.6
fix_rootpathint(){
  echo
  echo "6.2.6 Ensure root PATH Integrity"
  validpath="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"
  currpath=`echo $PATH`
  if [ "$validpath" == "$currpath" ]
  then
    echo_pass
  else
    grep -q "/usr/local/sbin" /root/.bash_profile
    if [ $? -eq 0 ]
    then
      echo_pass
    else
      sed -i s/"^PATH.*"/"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"/ /root/.bash_profile
      echo_pass
    fi
  fi
}

# 6.2.9 Ensure users own their home directories
check_userhomes(){
  echo
  echo "6.2.9 Ensure users own their home directories"
  numusers=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $7!="/sbin/nologin") {print $1}' | wc -l`
  users=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $7!="/sbin/nologin") {print $1}'`
  i=0
  for u in $users
  do
    home=`grep ^$u $PASSWD | cut -d":" -f6`
    own=`ls -ld $home | awk '{print $3}'` >/dev/null 2>&1
    if [ "$own" == "$u" ]
    then
      i=$(($i+1))
    fi
  done
  if [ $i -eq $numusers ]
  then
    echo_pass
  else
    echo_fail
  fi
}

fix_userhomes(){
  echo
  echo "6.2.9 Ensure users own their home directories"
  numusers=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $7!="/sbin/nologin") {print $1}' | wc -l`
  users=`egrep -v "^\+" $PASSWD | awk -F: '($1!="root" && $1!="sync" && $1!="idmadmin" && $1!="shutdown" && $1!="halt" && $7!="/sbin/nologin") {print $1}'`
  i=0
  for u in $users
  do
    home=`grep ^$u $PASSWD | cut -d":" -f6`
    own=`ls -ld $home | awk '{print $3}'`
    if [ "$own" == "$u" ]
    then
      i=$(($i+1))
    else
      chown $u $home
      i=$(($i+1))
    fi
  done
  if [ $i -eq $numusers ]
  then
    echo_pass
  fi
}

# 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
check_groups(){
  echo
  echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group"
  numgrp=`cut -d":" -f4 $PASSWD | wc -l`
  i=0
  for g in `cut -d":" -f4 $PASSWD`
  do
    gid=`grep -w $g $GROUP | cut -d":" -f3`
    if [ "$gid" == "$g" ]
    then
      i=$(($i+1))
    fi
  done
  if [ $numgrp -eq $i ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Can't Fix 6.2.5
fix_groups(){
  echo
  echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group"
  echo "Can't fix 6.2.5 it requires further analysis"
}

# 6.2.16 Ensure no duplicate UIDs exist
check_duplicatesuids(){
  echo
  echo "6.2.16 Ensure no duplicate UIDs exist"
  numuids=`cut -d":" -f3 $PASSWD | sort -n | uniq -c | wc -l`
  i=0
  for u in `cut -d":" -f3 $PASSWD | sort -n | uniq -c | awk '{print $1}'`
  do
    if [ $u -eq 1 ]
    then
      i=$(($i+1))
    fi
  done
  if [ $numuids -eq $i ]
  then
    echo_pass
  else
    echo_fail
  fi
}

# Fix 6.2.16
fix_duplicatesuids(){
  echo
  echo "6.2.16 Ensure no duplicate UIDs exist"
  echo "Too risky to fix duplicated UIDs manually"
}


main(){
# Ensure script is running as root
  uid=`id -u`
  if [ $uid -eq 0 ]
  then
# Using case sentence to execute accordingly with the script params
  case $1 in

    "-execute")
      fix_uncommonfs
      fix_fsmountopts
#      fix_autofs
      fix_autofsck
      fix_authreq
      fix_interactiveboot
      fix_coredumps
      fix_prelink
      fix_xinetd
#      fix_cups
      fix_nfsandrpc
      fix_clients
      fix_packetredir
      fix_icmpredir
      fix_secicmpredir
      fix_logsusppkt
      fix_rpfilter
      fix_acceptra
      fix_ipv6redir
#      fix_hostsdeny
#      fix_fwdenypolicy
#      fix_lotraffic
      fix_rsyslogfp
#      fix_rsyslogrh
      fix_logperms
      fix_cronfiles
      fix_cronatusrs
      fix_sshloglevel
#      fix_sshx11forward
      fix_sshmaxauth
      fix_sshignorerhosts
      fix_sshhostbasedauth
#      fix_sshrootlogin
      fix_sshpermitemptypwd
      fix_sshpermuserenv
      fix_sshciphers
      fix_sshmacalgo
#      fix_sshidletmout
      fix_sshlogingrctm
      fix_pwdcreation
      fix_faillock
      fix_pwdreuse
      fix_pwdexpiration
      fix_minpwdchng
      fix_inactivepwdlock
      fix_sysacctnologin
      fix_umask
#      fix_suaccess
      fix_shadowperms
      fix_passwdperms
      fix_rootpathint
      fix_userhomes
#      fix_groups
      fix_duplicatesuids
      ;;

    "-h")
      usage
      ;;

    "")
      check_uncommonfs
      check_fsmountopts
      check_autofs
      check_autofsck
      check_authreq
      check_interactiveboot
      check_coredumps
      check_prelink
      check_xinetd
      check_cups
      check_nfsandrpc
      check_clients
      check_packetredir
      check_icmpredir
      check_secicmpredir
      check_logsusppkt
      check_rpfilter
      check_acceptra
      check_ipv6redir
      check_hostsdeny
      check_fwdenypolicy
      check_lotraffic
      check_rsyslogfp
      check_rsyslogrh
      check_logperms
      check_cronfiles
      check_cronatusrs
      check_sshloglevel
      check_sshx11forward
      check_sshmaxauth
      check_sshignorerhosts
      check_sshhostbasedauth
      check_sshrootlogin
      check_sshpermitemptypwd
      check_sshpermuserenv
      check_sshciphers
      check_sshmacalgo
      check_sshidletmout
      check_sshlogingrctm
      check_pwdcreation
      check_faillock
      check_pwdreuse
      check_pwdexpiration
      check_minpwdchng
      check_inactivepwdlock
      check_sysacctnologin
      check_umask
      check_suaccess
      check_shadowperms
      check_passwdperms
      check_rootpathint
      check_userhomes
      check_groups
      check_duplicatesuids
      # nradev additions
      check_gpgcheck
      check_grub
      check_gdm
      check_xorg
      check_ssh_protocol
      check_ssh_users
      check_group_
      ;;

    *)
      usage
      ;;
  esac
  else
    echo "This script must be run as root"
    exit 1
  fi  
}
main "$*"

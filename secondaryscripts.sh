#!/usr/bin/env bash

# Ensure wireless interfaces are disabled (3.1.2)
{
    module_fix()
    {
        if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install\/bin\/(true|false)'; then
            echo -e " - setting module: \"$l_mname\" to be un-loadable"
            echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
        fi
        if lsmod | grep "$l_mname" > /dev/null 2>&1; then
            echo -e " - unloading module \"$l_mname\""
            modprobe -r "$l_mname"
        fi
        if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
            echo -e " - deny listing \"$l_mname\""
            echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
        fi
    }
    if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
        l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
        for l_mname in $l_dname; do
            module_fix
        done
    fi
}

# Ensure cron is restricted to authorized users (4.1.8)
{
    if dpkg-query -W cron > /dev/null 2>&1; then
        l_file="/etc/cron.allow"
        l_mask='0137'
        l_maxperm="$( printf '%o' $(( 0777 & ~$l_mask)) )"
        if [ -e /etc/cron.deny ]; then
            echo -e " - Removing \"/etc/cron.deny\""
            rm -f /etc/cron.deny
        fi
        if [ ! -e /etc/cron.allow ]; then
            echo -e " - creating \"$l_file\""
            touch "$l_file"
        fi
        while read l_mode l_fown l_fgroup; do
            if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
                echo -e " - Removing excessive permissions from \"$l_file\""
                chmod u-x,g-wx,o-rwx "$l_file"
            fi
            if [ "$l_fown" != "root" ]; then
                echo -e " - Changing owner on \"$l_file\" from: \"$l_fown\" to: \"root\""
                chown root "$l_file"
            fi
            if [ "$l_fgroup" != "crontab" ]; then
                echo -e " - Changing group owner on \"$l_file\" from: \"$l_fgroup\" to: \"crontab\""
                chgrp crontab "$l_file"
            fi
        done < <(stat -Lc '%#a %U %G' "$l_file")
    else
        echo -e "- cron is not installed on the system, no remediation required\n"
    fi
}

# Ensure at is restricted to authorized users (4.1.9)
{
    if dpkg-query -W at > /dev/null 2>&1; then
        l_file="/etc/at.allow"
        l_mask='0137'
        l_maxperm="$( printf '%o' $(( 0777 & ~$l_mask)) )"
        if [ -e /etc/at.deny ]; then
            echo -e " - Removing \"/etc/at.deny\""
            rm -f /etc/at.deny
        fi
        if [ ! -e /etc/at.allow ]; then
            echo -e " - creating \"$l_file\""
            touch "$l_file"
        fi
        while read l_mode l_fown l_fgroup; do
            if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
                echo -e " - Removing excessive permissions from \"$l_file\""
                chmod u-x,g-wx,o-rwx "$l_file"
            fi
            if [ "$l_fown" != "root" ]; then
                echo -e " - Changing owner on \"$l_file\" from: \"$l_fown\" to: \"root\""
                chown root "$l_file"
            fi
            if [ "$l_fgroup" != "root" ]; then
                echo -e " - Changing group owner on \"$l_file\" from: \"$l_fgroup\" to: \"root\""
                chgrp root "$l_file"
            fi
        done < <(stat -Lc '%#a %U %G' "$l_file")
    else
        echo -e "- cron is not installed on the system, no remediation required\n"
    fi
}

# GDM3 security/removal
if dpkg-query -W | grep -q gdm3; then
    # Ensure GDM login banner is configured (1.8.2)
    {
        l_pkgoutput=""
        if command -v dpkg-query > /dev/null 2>&1; then
            l_pq="dpkg-query -W"
        elif command -v rpm > /dev/null 2>&1; then
            l_pq="rpm -q"
        fi
        l_pcl="gdm gdm3" # Space seporated list of packages to check
        for l_pn in $l_pcl; do
            $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
        done    
        if [ -n "$l_pkgoutput" ]; then
            l_gdmprofile="gdm" # Set this to desired profile name IaW Local site policy
            l_bmessage="'Authorized uses only. All activity may be monitored and reported'" # Set to desired banner message
            if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
                echo "Creating profile \"$l_gdmprofile\""
                echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
            fi
            if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
                echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
                mkdir /etc/dconf/db/$l_gdmprofile.d/
            fi
            if ! grep -Piq '^\h*banner-message-enable\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
                echo "creating gdm keyfile for machine-wide settings"
                if ! grep -Piq -- '^\h*banner-message-enable\h*=\h*' /etc/dconf/db/$l_gdmprofile.d/*; then
                    l_kfile="/etc/dconf/db/$l_gdmprofile.d/01-banner-message"
                    echo -e "\n[org/gnome/login-screen]\nbanner-message-enable=true" >> "$l_kfile"
                else
                    l_kfile="$(grep -Pil -- '^\h*banner-message-enable\h*=\h*' /etc/dconf/db/$l_gdmprofile.d/*)"
                    ! grep -Pq '^\h*\[org\/gnome\/login-screen\]' "$l_kfile" && sed -ri '/^\s*banner-message-enable/ i\[org/gnome/login-screen]' "$l_kfile"
                    ! grep -Pq '^\h*banner-message-enable\h*=\h*true\b' "$l_kfile" && sed -ri 's/^\s*(banner-message-enable\s*=\s*)(\S+)(\s*.*$)/\1true \3//' "$l_kfile"
                    #sed -ri '/^\s*\[org\/gnome\/login-screen\]/ a\\nbanner-message-enable=true' "$l_kfile"
                fi
            fi
            if ! grep -Piq "^\h*banner-message-text=[\'\"]+\S+" "$l_kfile"; then
                sed -ri "/^\s*banner-message-enable/ a\banner-message-text=$l_bmessage" "$l_kfile"
            fi
            dconf update
        else
            echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n - No remediation required\n"
        fi
        echo "gdm3"
    }

    # Ensure GDM disable-user-list option is enabled (1.8.3)
    {
        l_gdmprofile="gdm"
        if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
            echo "Creating profile \"$l_gdmprofile\""
            echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
        fi
        if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
            echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
            mkdir /etc/dconf/db/$l_gdmprofile.d/
        fi
        if ! grep -Piq '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
            echo "creating gdm keyfile for machine-wide settings"
            if ! grep -Piq -- '^\h*\[org\/gnome\/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*; then
                echo -e "\n[org/gnome/login-screen]\n# Do not show the user list\ndisable-user-list=true" >> /etc/dconf/db/$l_gdmprofile.d/00-login-screen
            else
                sed -ri '/^\s*\[org\/gnome\/login-screen\]/ a\# Do not show the user list\ndisable-user-list=true' $(grep -Pil -- '^\h*\[org\/gnome\/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*)
            fi
        fi
        dconf update
        echo "gdm3_1"
    }
fi
# End of GDM3 shit

# Ensure all logfiles have appropriate access configured (5.1.3)
{
    l_op2="" l_output2=""
    l_uidmin="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"
    file_test_fix()
    {
        l_op2=""
        l_fuser="root"
        l_fgroup="root"
        if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then
            l_op2="$l_op2\n - Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive\n - Removing excess permissions"
            chmod "$l_rperms" "$l_fname"
        fi
        if [[ ! "$l_user" =~ $l_auser ]]; then
            l_op2="$l_op2\n - Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\"\n - Changing ownership to: \"$l_fuser\""
            chown "$l_fuser" "$l_fname"
        fi
        if [[ ! "$l_group" =~ $l_agroup ]]; then
            l_op2="$l_op2\n - Group owned by: \"$l_group\" and should be group owned by \"${l_agroup//|/ or }\"\n - Changing group ownership to: \"$l_fgroup\""
            chgrp "$l_fgroup" "$l_fname"
        fi
        [ -n "$l_op2" ] && l_output2="$l_output2\n - File: \"$l_fname\" is:$l_op2\n"
    }
    unset a_file && a_file=() # clear and initialize array
    # Loop to create array with stat of files that could possibly fail one of the audits
    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && a_file+=("$(stat -Lc '%n^%#a^%U^%u^%G^%g' "$l_file")")
    done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)
    while IFS="^" read -r l_fname l_mode l_user l_uid l_group l_gid; do
        l_bname="$(basename "$l_fname")"
        case "$l_bname" in
            lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
                perm_mask='0113'
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_rperms="ug-x,o-wx"
                l_auser="root"
                l_agroup="(root|utmp)"
                file_test_fix
                ;;
            secure | auth.log | syslog | messages)
                perm_mask='0137'
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_rperms="u-x,g-wx,o-rwx"
               l_auser="(root|syslog)"
                l_agroup="(root|adm)"
                file_test_fix
                ;;
            SSSD | sssd)
                perm_mask='0117'
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_rperms="ug-x,o-rwx"
                l_auser="(root|SSSD)"
                l_agroup="(root|SSSD)"
                file_test_fix
                ;;
            gdm | gdm3)
                perm_mask='0117'
                l_rperms="ug-x,o-rwx"
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_auser="root"
                l_agroup="(root|gdm|gdm3)"
                file_test_fix
                ;;
            *.journal | *.journal~)
                perm_mask='0137'
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_rperms="u-x,g-wx,o-rwx"
                l_auser="root"
                l_agroup="(root|systemd-journal)"
                file_test_fix
                ;;
            *)
                perm_mask='0137'
                maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
                l_rperms="u-x,g-wx,o-rwx"
                l_auser="(root|syslog)"
                l_agroup="(root|adm)"
                if [ "$l_uid" -lt "$l_uidmin" ] && [ -z "$(awk -v grp="$l_group" -F: '$1==grp {print $4}' /etc/group)" ]; then
                    if [[ ! "$l_user" =~ $l_auser ]]; then
                        l_auser="(root|syslog|$l_user)"
                    fi
                    if [[ ! "$l_group" =~ $l_agroup ]]; then
                        l_tst=""
                        while l_out3="" read -r l_duid; do
                            [ "$l_duid" -ge "$l_uidmin" ] && l_tst=failed
                        done <<< "$(awk -F: '$4=='"$l_gid"' {print $3}' /etc/passwd)"
                        [ "$l_tst" != "failed" ] && l_agroup="(root|adm|$l_group)"
                    fi
                fi
                file_test_fix
                ;;
        esac
    done <<< "$(printf '%s\n' "${a_file[@]}")"
    unset a_file # Clear array
    # If all files passed, then we report no changes
    if [ -z "$l_output2" ]; then
        echo -e "- All files in \"/var/log/\" have appropriate permissions and ownership\n - No changes required\n"
    else
        # print report of changes
        echo -e "\n$l_output2"
    fi
}

# Configure auditd rules
#-----------------------------------------
# Ensure changes to system administration scope (sudoers) is collected (5.2.3.1)
printf "
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
" >> /etc/audit/rules.d/50-scope.rules
augenrules --load

# Ensure actions as another user are always logged (5.2.3.2)
printf "
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
" >> /etc/audit/rules.d/50-user_emulation.rules
augenrules --load

# Ensure events that modify the sudo log file are collected (5.2.3.3)
{
    SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g')
    [ -n "${SUDO_LOG_FILE}" ] && printf "
    -w ${SUDO_LOG_FILE} -p wa -k sudo_log_file
    " >> /etc/audit/rules.d/50-sudo.rules || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
}
augenrules --load

# Ensure events that modify date and time information are collected (5.2.3.4)
printf "
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
" >> /etc/audit/rules.d/50-time-change.rules 
augenrules --load

# Ensure events that modify the system's network environment are collected (5.2.3.5)
printf "
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
" >> /etc/audit/rules.d/50-system_locale.rules
augenrules --load

# Ensure use of privileged commands are collected (5.2.3.6)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    AUDIT_RULE_FILE="/etc/audit/rules.d/50-privileged.rules"
    NEW_DATA=()
    for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print$1}'); do
        readarray -t DATA < <(find "${PARTITION}" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }')
            for ENTRY in "${DATA[@]}"; do
                NEW_DATA+=("${ENTRY}")
            done
    done
    readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
    COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
    printf '%s\n' "${COMBINED_DATA[@]}" | sort -u > "${AUDIT_RULE_FILE}"
}
augenrules --load

# Ensure unsuccessful file access attempts are collected (5.2.3.7)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
    " >> /etc/audit/rules.d/50-access.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure events that modify user/group information are collected (5.2.3.8)
printf "
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
" >> /etc/audit/rules.d/50-identity.rules
augenrules --load

# Ensure discretionary access control permission modification events are collected (5.2.3.9)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S
    setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S
    setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    " >> /etc/audit/rules.d/50-perm_mod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure successful file system mounts are collected (5.2.3.10)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
    -a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
    " >> /etc/audit/rules.d/50-mounts.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure session initiation information is collected (5.2.3.11)
printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" >> /etc/audit/rules.d/50-session.rules
augenrules --load

# Ensure login and logout events are collected (5.2.3.12)
printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> /etc/audit/rules.d/50-login.rules
augenrules --load

# Ensure file deletion events by users are collected (5.2.3.13)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
    -a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
    " >> /etc/audit/rules.d/50-delete.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure events that modify the system's Mandatory Access Controls are collected (5.2.3.14)
printf "
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
" >> /etc/audit/rules.d/50-MAC-policy.rules
augenrules --load

# Ensure successful and unsuccessful attempts to use the chcon command are recorded (5.2.3.15)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
    " >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure successful and unsuccessful attempts to use the setfacl command are recorded (5.2.3.16)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
    " >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure successful and unsuccessful attempts to use the chacl command are recorded (5.2.3.17)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
    " >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure successful and unsuccessful attempts to use the usermod command are recorded (5.2.3.18)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
    " >> /etc/audit/rules.d/50-usermod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure kernel module loading unloading and modification is collected (5.2.3.19)
{
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && printf "
    -a always,exit -F arch=b64 -S
    init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
    -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
    " >> /etc/audit/rules.d/50-kernel_modules.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}
augenrules --load

# Ensure the audit configuration is immutable (5.2.3.20)
printf -- "-e 2
" >> /etc/audit/rules.d/99-finalize.rules
augenrules --load

# Configure auditd file access (5.2.4)
#-----------------------------------------
# Ensure audit log files are mode 0640 or less permissive (5.2.4.1)
[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
# Ensure only authorized users own audit log files (5.2.4.2)
[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +
# Ensure only authorized groups are assigned ownership of audit log files (5.2.4.3)
find $(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)) -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +
sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf
systemctl restart auditd
# Ensure the audit log directory is 0750 or more restrictive (5.2.4.4)
chmod g-w,o-rwx "$(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf))"
# Ensure audit configuration files are 640 or more restrictive (5.2.4.5)
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
# Ensure audit configuration files are owned by root (5.2.4.6)
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
# Ensure audit configuration files belong to group root (5.2.4.7)
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
# Ensure audit tools are 755 or more restrictive (5.2.4.8)
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
# Ensure audit tools are owned by root (5.2.4.9)
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
# Ensure audit tools belong to group root (5.2.4.10)
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# Ensure world writable files and directories are secured (6.1.11)
{
    l_smask='01000'
    a_path=(); a_arr=() # Initialize array
    a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "/sys/kernel/security/apparmor/*" -a ! -path "/snap/*" -a ! -path "/sys/fs/cgroup/memory/*")
    while read -r l_bfs; do
        a_path+=( -a ! -path ""$l_bfs"/*")
    done < <(findmnt -Dkerno fstype,target | awk '$1 ~ /^\s*(nfs|proc|smb)/ {print $2}')
    # Populate array with files
    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && a_arr+=("$(stat -Lc '%n^%#a' "$l_file")")
    done < <(find / \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
    while IFS="^" read -r l_fname l_mode; do # Test files in the array
        if [ -f "$l_fname" ]; then # Remove excess permissions from WW files
            echo -e " - File: \"$l_fname\" is mode: \"$l_mode\"\n - removing write permission on \"$l_fname\" from \"other\""
            chmod o-w "$l_fname"
        fi
        if [ -d "$l_fname" ]; then
            if [ ! $(( $l_mode & $l_smask )) -gt 0 ]; then # Add sticky bit
                echo -e " - Directory: \"$l_fname\" is mode: \"$l_mode\" and doesn't have the sticky bit set\n - Adding the sticky bit"
                chmod a+t "$l_fname"
            fi
        fi
    done < <(printf '%s\n' "${a_arr[@]}")
    unset a_path; unset a_arr # Remove array
}
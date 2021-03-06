#!/usr/bin/bash

dir=$1
ver=$(echo $dir  | rev | cut -d / -f 2 | rev)
path="$dir/LiquidSecurity-NFBE-$ver/liquidsec_pf_vf_driver"
buildir="$dir/"
bin="$buildir/bin/"
data="$buildir/data"
build="$buildir/"
nfbe="$buildir/nfbe0"
alias src="cd $path"
alias bin="cd $bin"
alias data="cd $data"
alias build="cd $build"
alias nfbe="cd $nfbe"
name="PARTITION_$2"
log="log$2"
sign="sign$2"
binary="bin$2"
pcert="pcert$2"
hcert="hcert$2"
alias hsmload="sh $path/driver_load.sh hsm_load $path/src && dmesg -c"
alias hsmunload="sh $path/driver_load.sh hsm_unload"
alias hsmreload="sh $path/driver_load.sh hsm_reload $path/src && dmesg -c"

if test $3 -eq 1; then
alias createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 2 -f 1 -an csr -b 1 -i $2 -a"
fi
if test $3 -eq 0; then
alias createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 2 -f 1 -an csr -b 1 -i $2"
fi

#alias createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 63 -f 1 -an csr -b 1 -i $1"
defmaster="$bin/Cfm2MasterUtil singlecmd loginHSM -p default -s cavium -u CO"
alias defmaster="$bin/Cfm2MasterUtil singlecmd loginHSM -p default -s cavium -u CO"
master="$bin/Cfm2MasterUtil singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
alias master="$bin/Cfm2MasterUtil singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
alias masterzeroize="$bin/Cfm2MasterUtil singlecmd zeroizeHSM"
alias masterinit="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s cavium -p default initHSM -p so12345 -sO crypto_officer -a 0 -f $data/hsm_config"
alias cfmzeroize="$bin/Cfm2Util -p $name singlecmd zeroizeHSM"
alias def="$bin/Cfm2Util -p $name singlecmd loginHSM -p default -s cavium -u CO"
alias au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
alias cu="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s crypto_user -u CU"
alias co="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
alias pek="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s crypto_officer -p so12345 generatePEK"
alias kek="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK"
alias cfminit="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s cavium -p default initHSM -p so12345 -sO crypto_officer -u user123 -sU crypto_user -a 0 -f $data/hsm_config"
alias createau="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO createUser -u AU -s app_user -p user123"
alias delau="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO deleteUser -u AU -n app_user"
alias au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
alias deletepart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer deletePartition -n $name"
alias forcedel="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer deletePartition -f -n $name"
alias hsmshutdown="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer shutdownHSM"
alias singlecmd="$bin/Cfm2Util -p $name singlecmd "

### Audit Log retrieval Commands ###
au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
alias getlog="$au getAuditLogs -l $binary -s $sign"
alias colog="$def getAuditLogs -l $binary -s $sign"
alias h_cert="$bin/Cfm2Util -p $name singlecmd getCert -f $hcert -s 2"
alias p_cert="$bin/Cfm2Util -p $name singlecmd getCert -f $pcert -s 16"
alias convert="$bin/Cfm2AuditLogUtil -b $binary -s $sign -pcert $pcert -hcert $hcert -t $log"
alias finalize="$master finalizeLogs -n $name"

ccd="/home/amazon/build/cc27/bin"
alias ccd="cd /home/amazon/build/cc27/bin"
alias ccu="$ccd/Cfm3Util singlecmd loginHSM -p user123 -s crypto_user -u CU"




if test $2 -eq 1; then
createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 2 -f 1 -an csr -b 1 -i $1 -a"
fi
if test $2 -eq 0; then
createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 2 -f 1 -an csr -b 1 -i $1"
fi

#createpart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345 createPartition -n $name -s 1024 -c 1024 -d 63 -f 1 -an csr -b 1 -i $1"
defmaster="$bin/Cfm2MasterUtil singlecmd loginHSM -p default -s cavium -u CO"
defmaster="$bin/Cfm2MasterUtil singlecmd loginHSM -p default -s cavium -u CO"
master="$bin/Cfm2MasterUtil singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
master="$bin/Cfm2MasterUtil singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
masterzeroize="$bin/Cfm2MasterUtil singlecmd zeroizeHSM"
masterinit="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s cavium -p default initHSM -p so12345 -sO crypto_officer -a 0 -f $data/hsm_config"
cfmzeroize="$bin/Cfm2Util -p $name singlecmd zeroizeHSM"
def="$bin/Cfm2Util -p $name singlecmd loginHSM -p default -s cavium -u CO"
au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
cu="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s crypto_user -u CU"
co="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO"
pek="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s crypto_officer -p so12345 generatePEK"
kek="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK"
cfminit="$bin/Cfm2Util -p $name singlecmd loginHSM -u CO -s cavium -p default initHSM -p so12345 -sO crypto_officer -u user123 -sU crypto_user -a 0 -f $data/hsm_config"
createau="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO createUser -u AU -s app_user -p user123"
delau="$bin/Cfm2Util -p $name singlecmd loginHSM -p so12345 -s crypto_officer -u CO deleteUser -u AU -n app_user"
au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
deletepart="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer deletePartition -n $name"
forcedel="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer deletePartition -f -n $name"
hsmshutdown="$bin/Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer shutdownHSM"
singlecmd="$bin/Cfm2Util -p $name singlecmd "

### Audit Log retrieval Commands ###
au="$bin/Cfm2Util -p $name singlecmd loginHSM -p user123 -s app_user -u AU"
getlog="$au getAuditLogs -l $binary -s $sign"
colog="$def getAuditLogs -l $binary -s $sign"
h_cert="$bin/Cfm2Util -p $name singlecmd getCert -f $hcert -s 2"
p_cert="$bin/Cfm2Util -p $name singlecmd getCert -f $pcert -s 16"
convert="$bin/Cfm2AuditLogUtil -b $binary -s $sign -pcert $pcert -hcert $hcert -t $log"
finalize="$master finalizeLogs -n $name"

ccd="/home/amazon/build/cc27/bin"
ccd="cd /home/amazon/build/cc27/bin"
ccu="$ccd/Cfm3Util singlecmd loginHSM -p user123 -s crypto_user -u CU"
alias getpolicy="$co getPolicy"
alias set258="$master setPolicy -id 258 -n $name"
alias set513="$co setPolicy -id 513 -value 1"
alias set514="$co setPolicy -id 514 -value 1"
alias set515="$co setPolicy -id 515 -value 1"
alias unset258="$co setPolicy -id 258 -value 0"
alias unset513="$co setPolicy -id 513 -value 0"
alias unset514="$co setPolicy -id 514 -value 0"
alias unset515="$co setPolicy -id 515 -value 0"
getpolicy="$co getPolicy"
set258="$master setPolicy -id 258 -n $name"
set513="$co setPolicy -id 513 -value 1"
set514="$co setPolicy -id 514 -value 1"
set515="$co setPolicy -id 515 -value 1"
unset258="$co setPolicy -id 258 -value 0"
unset513="$co setPolicy -id 513 -value 0"
unset514="$co setPolicy -id 514 -value 0"
unset515="$co setPolicy -id 515 -value 0"

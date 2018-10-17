pkg="LiquidSecurity-NFBE-2.03-15-tag-22.tgz"
for i in {3..3}; do

echo "Copying Package to VM 30.0.0.$i"
sshpass -p a scp $pkg 30.0.0.$i:

echo "Copying installer"
sshpass -p a scp pkg-Install.sh 30.0.0.$i:

echo "Creating bin folder"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "mkdir -p /root/build/1522"

echo "Executing Installer"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "sh /root/pkg-Install.sh"

echo "Copying script to install driver and load driver"
sshpass -p a scp sc 30.0.0.$i:
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "sh sc" ; sleep 10

j=$(( $i - 1 ))
cmd1="/root/build/1522/bin/Cfm2Util -p "
zeroize="singlecmd zeroizeHSM"
init="singlecmd loginHSM -u CO -s cavium -p default initHSM -sO crypto_officer -p so12345 -sU crypto_user -u user123 -a 0 -f /root/build/1522/data/hsm_config"
kek="singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK"
au="singlecmd loginHSM -u CO -s crypto_officer -p so12345 createUser -u AU -s app_user -p user123"
echo "Zeroize, Initialize, generateKEK and Create AU"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "$cmd1 PARTITION_$j $zeroize"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "$cmd1 PARTITION_$j $init"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "$cmd1 PARTITION_$j $kek"
sshpass -p a ssh -o StrictHostKeyChecking=no 30.0.0.$i "$cmd1 PARTITION_$j $au"

echo "Copying Package to VM 30.0.0.$i"
sshpass -p a scp amazon_conf 30.0.0.$i:
done

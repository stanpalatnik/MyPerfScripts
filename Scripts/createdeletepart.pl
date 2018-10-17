#!/usr/bin/perl

use strict;
use warnings;

open(FH, ">log.txt");
system("date");
my ($date, @resp);
my $vmip   = "30.0.0.2";
my $bin    = "/home/amazon/build/1527/bin/";
my $util   = "/home/amazon/build/1527/bin/Cfm2Util";
my $driver = "/home/amazon/sdk/LiquidSecurity-NFBE-2.03-15-tag-27/liquidsec_pf_vf_driver";
my $master = "/home/amazon/build/1527/bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345";
my $createpart = "$master createPartition  -n  PARTITION_1  -s  1024  -c  1024  -d  2  -f  1  -an  csr  -b  1  -i  1";
my $driverload = "sh $driver/driver_load.sh hsm_reload $driver/src 2";
my $vmbindir   = "/root/build/1527/";
my $vmdrvdir   = "/root/LiquidSecurity-NFBE-2.03-15-tag-27/liquidsec_pf_vf_driver/";
my $vmdriverload = "sh $vmdrvdir/driver_load.sh hsm_reload $vmdrvdir/src";

foreach my $i (1..999999){
    $date=`date`; print "Loop $i: $date";
    print FH "Creating Partition\n";
    @resp = `$createpart`; print FH "@resp\n\n";
    sleep 2;
    print FH "Reloading Driver\n";
    @resp = `$driverload`; print FH "@resp\n\n";
#    `dmesg -c`;
    my $state = `cat /proc/cavium_n3fips/driver_state`;
    my $count=0;
    while ($state !~/SECURE_OPERATIONAL_STATE/){
        $state = `cat /proc/cavium_n3fips/driver_state`;
        last if ($state=~/SECURE_OPERATIONAL_STATE/);
        if ($count == 16) {
            @resp=`dmesg`; print FH "\n@resp\n";
            exit;
        }
        $count++;
        sleep 5;
    }
    @resp = `lsmod | grep liquid`; print FH "Checking Driver Loaded: @resp\n\n";
    
    print FH "Launching VM\n";
    my $cmd = "/home/qemu-kvm-1.2.0/x86_64-softmmu//qemu-system-x86_64 -hda /halb_home/HALB/images//fedora1.qcow2 -smp 2 -m 2048 -net nic,model=virtio,macaddr=04:05:06:00:e1:11,vlan=1 -net tap,vlan=1,ifname=tap1,script=/etc/qemu-ifup-virbr0,downscript=/etc/qemu-ifdown-virbr0 -boot c -device pci-assign,host=02:10.0 --nographic > /dev/null &";
    @resp = `$cmd`; print FH "@resp\n\n";
    sleep 30;
    
    print FH "Loading Driver inside VM\n";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$vmdriverload\"`; print FH "@resp\n\n";
    sleep 15;
    print FH "Initializing Partition, generating KEK and RSA KeyPair in VM\n";
    $cmd = "$vmbindir/bin/Cfm2Util singlecmd loginHSM -u CO -s cavium -p default initHSM -sU crypto_user -u user123 -sO crypto_officer -p so12345 -a 0 -f $vmbindir/data/hsm_config";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
    $cmd = "$vmbindir/bin/Cfm2Util singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
    $cmd = "$vmbindir/bin/Cfm2Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65537 -l rsa";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
    
    print FH "Shutting down VM\n";
    `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip "nohup shutdown -h now &>/dev/null & exit"`;   sleep 3;
    my $qemuprocess = `pgrep -l qemu | awk '{print \$1}'`;
    chomp $qemuprocess; print FH "qemuprocessID: $qemuprocess\n";
    $count=0;
    while ($qemuprocess ne ''){
        $qemuprocess = `pgrep -l qemu | awk '{print \$1}'`;
        chomp $qemuprocess; print FH "qemuprocessID: $qemuprocess\n";
        if ($count == 16) {
            `kill -9 $qemuprocess`; sleep 5;
            $qemuprocess = `pgrep -l qemu | awk '{print \$1}'`;
            if ($qemuprocess ne ''){
                print FH "Unable to kill QEMU even after proper shutdown and kill command\n";
                exit;
            }else{
                chomp $qemuprocess; print FH "qemuprocessID after Kill Command: $qemuprocess\n";
            }
        }
        $count++;
        sleep 5;
    }
    
    print FH "Deleting Partition\n";
    @resp = `$master deletePartition -n PARTITION_1 -f`;  print FH "@resp\n\n";
    sleep 3; print "\n";
}

system("date");

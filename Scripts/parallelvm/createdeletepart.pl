#!/usr/bin/perl

use strict;
use warnings;

open(FH, ">log.txt");
system("date");
my ($cmd, $date, @resp, $createpart);
my $vmip1  = "192.168.122.202";
my $vmip2  = "192.168.122.203";
my $bin    = "/home/amazon/build/1528/bin/";
my $util   = "/home/amazon/build/1528/bin/Cfm2Util";
my $driver = "/home/amazon/sdk/LiquidSecurity-NFBE-2.03-15-tag-28/liquidsec_pf_vf_driver";
my $master = "/home/amazon/build/1528/bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345";
my $driverload = "sh $driver/driver_load.sh hsm_reload $driver/src 2";
my $vmbindir   = "/root/build/1528/";
my $vmdrvdir   = "/root/LiquidSecurity-NFBE-2.03-15-tag-28/liquidsec_pf_vf_driver/";
my $vmdriverload = "sh $vmdrvdir/driver_load.sh hsm_reload $vmdrvdir/src";

print FH "Reloading Driver\n";
@resp = `$driverload`; print FH "@resp\n\n";
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

foreach my $i (1..20){

    $date=`date`; print "Loop $i";

    if ($i eq 1){
        print FH "Creating Partition 1: $date\n";
        $createpart = "$master createPartition  -n  PARTITION_1  -s  1024  -c  1024  -d  2  -f  1  -an  csr  -b  1  -i  1";
        @resp = `$createpart`; print FH "@resp\n\n";
        sleep 2;
        print FH "Launching VM 1\n";
        $cmd = "/home/qemu-kvm-1.2.0/x86_64-softmmu//qemu-system-x86_64 -hda /halb_home/HALB/images//fedora1.qcow2 -smp 2 -m 2048 -net nic,model=virtio,macaddr=04:05:06:00:e1:11,vlan=1 -net tap,vlan=1,ifname=tap1,script=/etc/qemu-ifup-virbr2,downscript=/etc/qemu-ifdown-virbr2 -boot c -device pci-assign,host=02:10.0 --nographic > /dev/null &";
        @resp = `$cmd`; print FH "@resp\n\n";
        sleep 30;
        &loadvmdriver($vmip1, 1);

        $cmd = "$vmbindir/bin/Cfm2Util singlecmd loginHSM -u CU -s crypto_user -p user123 findKey";
        @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 \"$cmd\"`; print FH "FINDKEY\n@resp\n\n";

        `sshpass -p a scp /root/netlink1.conf $vmip1:/root/`;
        $cmd="$vmbindir/bin/AuditLogDaemon -f /root/netlink1.conf";
        `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 "nohup $cmd &>/dev/null & exit"`;
        @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 "pgrep -l qemu"`; print FH "AuditLogDaemon: @resp\n";

        `sshpass -p a scp /root/vm $vmip1:/root/`;
        $cmd="sh /root/vm";
        `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 "nohup $cmd &>/dev/null & exit"`;
    }

    print FH "Creating Partition 2: $date\n";
    $createpart = "$master createPartition  -n  PARTITION_2  -s  1024  -c  1024  -d  2  -f  1  -an  csr  -b  1  -i  2";
    @resp = `$createpart`; print FH "@resp\n\n";
    sleep 2;

    print FH "Launching VM 2\n";
    $cmd = "/home/qemu-kvm-1.2.0/x86_64-softmmu//qemu-system-x86_64 -hda /halb_home/HALB/images//fedora2.qcow2 -smp 2 -m 2048 -net nic,model=virtio,macaddr=04:05:06:00:e1:12,vlan=1 -net tap,vlan=1,ifname=tap2,script=/etc/qemu-ifup-virbr2,downscript=/etc/qemu-ifdown-virbr2 -boot c -device pci-assign,host=02:10.2 --nographic > /dev/null &";
    @resp = `$cmd`; print FH "@resp\n\n";
    sleep 30;
 
    &loadvmdriver($vmip2, 2);
    
    print FH "Shutting down VM2\n";
    `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip2 "nohup shutdown -h now &>/dev/null & exit"`;   sleep 5;
    my $qemuprocess = `ps aux | grep qemu | grep fedora2 | awk '{print \$2}'`;
    &checkprocess($qemuprocess, "fedora2");
    
    &deletepartition(2);
}

## Executing findKey before shutting down VM
$cmd = "$vmbindir/bin/Cfm2Util singlecmd loginHSM -u CU -s crypto_user -p user123 findKey";
@resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 \"$cmd\"`; print FH "FINDKEY\n@resp\n\n";
print FH "Shutting down VMs\n";
`sshpass -p a ssh -o StrictHostKeyChecking=no $vmip1 "nohup shutdown -h now &>/dev/null & exit"`;   sleep 3;
my $qemuprocess = `ps aux | grep qemu | grep fedora1 | awk '{print \$2}'`;
&checkprocess($qemuprocess, "fedora1");
&deletepartition(1);

sub checkprocess
{
    my @resp;
    my $count=0;
    my $qemuprocess = shift;
    my $string = shift;
    chomp $qemuprocess; print FH "qemuprocessID: $qemuprocess\n";

    while ($qemuprocess ne ''){
        $qemuprocess = `ps aux | grep qemu | grep $string | awk '{print \$2}`;
        chomp $qemuprocess; print FH "qemuprocessID: $qemuprocess\n";
        if ($count == 16) {
            `kill -9 $qemuprocess`; sleep 5;
            $qemuprocess = `ps aux | grep qemu | grep $string | awk '{print \$2}`;
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
}

sub loadvmdriver
{
    my @resp;
    my $vmip=shift;
    my $pnumber=shift;
    print FH "Loading Driver inside VM\n";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$vmdriverload\"`; print FH "@resp\n\n";
    sleep 15;
    print FH "Initializing Partition, generating KEK and RSA KeyPair in VM\n";
    my $cmd = "$vmbindir/bin/Cfm2Util -p PARTITION_$pnumber singlecmd loginHSM -u CO -s cavium -p default initHSM -sU crypto_user -u user123 -sO crypto_officer -p so12345 -a 0 -f $vmbindir/data/hsm_config";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
    $cmd = "$vmbindir/bin/Cfm2Util -p PARTITION_$pnumber singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
    $cmd = "$vmbindir/bin/Cfm2Util -p PARTITION_$pnumber singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65537 -l rsa";
    @resp = `sshpass -p a ssh -o StrictHostKeyChecking=no $vmip \"$cmd\"`; print FH "@resp\n\n";
    sleep 1;
}

sub deletepartition
{
    my $pnumber = shift;
    print FH "Deleting Partition $pnumber\n";
    @resp = `$master deletePartition -n PARTITION_$pnumber -f`;  print FH "@resp\n\n";
    sleep 3; print "\n";
}

system("date");


#my $qemuprocess = `pgrep -l qemu | awk '{print \$1}'`;

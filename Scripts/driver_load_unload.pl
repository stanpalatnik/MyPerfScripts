#!/usr/bin/perl

my $vm_driver_dir="/root/LiquidSecurity-NFBE-2.03-15-tag-26/liquidsec_pf_vf_driver/";
open(FH, ">reload.txt") or die "Couldn't open file file.txt, $!";

my $date=`date`;
print FH "@a\n$date\n";
foreach my $i (1..999999){
    print "Reload loop $i\n";
    print FH "Reload loop $i\n";
    my @a=`sh $vm_driver_dir/driver_load.sh hsm_unload`;
    print FH "@a\n";
    sleep 2;
    @a=`sh $vm_driver_dir/driver_load.sh hsm_load $vm_driver_dir/src 32`;
    sleep 120;
    print FH "@a\n";
    my $date=`date`;
    my $dmesg=`dmesg`;
    print FH "@a\nDATE: $date\n$dmesg\n";
    `dmesg -c`;
}

$date=`date`;
print FH "@a\n$date\n";
close(FH);

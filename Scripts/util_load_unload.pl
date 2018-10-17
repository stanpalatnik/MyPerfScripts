#!/usr/bin/perl

my $vm_driver_dir="/root/LiquidSecurity-NFBE-2.03-15-tag-27/liquidsec_pf_vf_driver/";
open(FH, ">pkpspeed_block.txt") or die "Couldn't open file file.txt, $!";

my $date=`date`;
print FH "$date\n";
foreach my $i (1..999999){
    print "pkpspeed loop $i\n";
    print FH "pkpspeed loop $i\n";
    my @a=system("printf \"B\n50\n10\nC\n32\nX\" | ./pkpspeed -s crypto_user -p user123 >&/tmp/txt");
    sleep 2;
    my @contents=`cat /tmp/txt`;
    print FH "@contents\n";
    my $date=`date`;
    my $dmesg=`dmesg`;
    print FH "DATE: $date\n$dmesg\n";
    `dmesg -c`;
}

$date=`date`;
print FH "$date\n";
close(FH);

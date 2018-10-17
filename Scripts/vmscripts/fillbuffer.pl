use strict;
use warnings;

open(my $fh, ">detail.txt");
my ($cu, $au);
my $numlogs = (defined $ARGV[0]) ? $ARGV[0] : 2500;
my $numparts =  ((defined $ARGV[1]) && ($ARGV[1] eq "all")) ? 32 : 1;
my $partition_name = "PARTITION_$ARGV[1]" if ($numparts ne 32);
my $numloops = 1;

my $cfm2util = "/root/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util";
foreach my $loop (0..0){
    my $date=`date`; chomp $date;
    print $fh "Start Time: $date, $loop\n";
    foreach my $partition (1..$numparts){
        my $partName = (($ARGV[1] ne "all")) ? $partition_name : "PARTITION_$partition";
        print $fh "Filling log on partition: $partName";
        $cu = "$cfm2util -p $partName singlecmd loginHSM -u CU -s crypto_user -p user123";
        $au = "$cfm2util -p $partName singlecmd loginHSM -u AU -s app_user -p user123";
        `$au getAuditLogs -l log.bin -s log.sign`;
        my $date=`date`; chomp $date;
        foreach my $i (0..$numlogs){
            my @resp = `$cu`;
            print $fh "count: $i\n";
            print $fh "@resp\n\n";
            #if (grep(/buffer/, @resp))
            if ($i eq $numlogs){
#                `$au getAuditLogs -l log.bin -s log.sign`;
                 last;
            }
        }
        print $fh "\n\n";
    }
    $date=`date`; chomp $date;
    print "Finished Loop $loop\n";
    print $fh " ----- End Time: $date ----- \n";
}

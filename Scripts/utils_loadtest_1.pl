#!/usr/bin/perl 
#===============================================================================
#
#         FILE: loop.pl
#
#        USAGE: ./loop.pl  
#
#  DESCRIPTION: 
#
#      OPTIONS: ---
# REQUIREMENTS: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: YOUR NAME (), 
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 09/21/2017 06:30:55 PM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use File::Slurp;

if (($ARGV[0] eq "help") || (@ARGV eq 0)){
    print "options for argument 0 : Number of Loops to iterate\n";
    print "options for argument 1 : Number of Partitions to be selected\n";
    exit;
}

my $sdk     = "/root/LiquidSecurity-NFBE-2.03-12/liquidsec_pf_vf_driver";
my $bindist = "/usr/local/bin";
my $fh = open(FH, ">log.txt");

my $date = `date`; chomp $date;
print FH " \n START $date \n ";
print " \n START $date \n ";
my $num_loops = $ARGV[0];
my $num_partitions = $ARGV[1];

system("rm -rf partition*");
system("rm -rf fail_*");

foreach my $j (1..$num_loops){
    foreach my $i (1..$num_partitions){
        my $co = "$bindist/Cfm2Util ";
        my $log = "partition$i";
        #my @a = `./test_ssl -s crypto_user -p user123 -pname PARTITION_$i`;
        #system("./test_crypto -s crypto_user -p user123 -pname PARTITION_$i >&$log&");
        system("./Cfm2Util -p PARTITION_$i singlecmd loginHSM -u CU -s crypto_user -p user123 >>$log&");
        #open(PH, ">>$log");
        #print PH "@a\n";
        #close PH;
    }
#    sleep 20;
    $date = `date`; chomp $date;
    print " \n END LOOP $j $date \n ";
    print FH " \n END LOOP $j $date \n ";
}

$date = `date`; chomp $date;
print FH " \n END $date \n ";
close FH;

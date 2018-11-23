#!/usr/bin/perl

use strict;
use warnings;

open(FH,"<$ARGV[0]") or die "Could not find file\n";
my @lines = <FH>;
my (@all_nums, $usecs, $secs, $kps);
foreach my $line (@lines){
    chomp $line;
    if($line=~/start:/){
        @all_nums = $line =~ /(\d+)/g;
        $secs  = $all_nums[2] - $all_nums[0];
        $usecs = $all_nums[3] - $all_nums[1];
        $kps   = $secs/100;
        print "$secs secs and $usecs usecs, kps: $kps\n";
    }
}

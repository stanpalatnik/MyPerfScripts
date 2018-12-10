#!/usr/bin/perl

use Data::Dumper;

open(FH, "<Result_n3fips_automation.log") or die "Could not open the file.\n";
my @lines = <FH>;
my $counter=0; my $occurence=0; my $failc=0; my %hash;

foreach my $line (@lines)
{
    chomp $line;
    $line=~ s/^\s+|\s+$//g;
    if ($line=~/FIPS State/){
        $counter++;
        $occurence=1;
        $failc=0;
        $hash{$counter}{fips}=$line;
    }
    if ($occurence){
        $hash{$counter}{certauth}=$line if ($line=~/Cert Auth/);
        $hash{$counter}{utility}=$line if ($line=~/Utility Name/);
        $hash{$counter}{group}=$line if ($line=~/Group Name/);
        $hash{$counter}{command}=$line if ($line=~/Command Name/);
        $hash{$counter}{testtype}=$line if ($line=~/Test Type/);

        if ($line=~/FAIL/){
            $failc++;
            $hash{$counter}{$failc}{test}=$line if ($line=~/FAIL/);
            $testno = `echo \"$hash{$counter}{$failc}{test}\" \| grep \"FAIL\" \| awk '{print \$1}'`;     chomp $testno;
            $groupname = `echo \"$hash{$counter}{group}\" \| grep \"Group Name\" \| cut -d : -f 2`;       chomp $groupname;
            $commandname = `echo \"$hash{$counter}{command}\" \| grep \"Command Name\" \| cut -d : -f 2`; chomp $commandname;
            $testtype = `echo \"$hash{$counter}{testtype}\" \| grep \"Test Type\" \| cut -d : -f 2`;      chomp $testtype;
            print "testno: $testno, $groupname: $groupname, commandname: $commandname, testtype: $testtype\n";
        }
    }
}
print "\n";
close FH;

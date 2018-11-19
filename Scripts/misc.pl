#!/usr/bin/perl

use strict;
use warnings;

my $str="string1t";
my $b=chomp $str;
print $b;
#print chomp($str);
print "\n$str\n";
print chop $str;
print "\n";

$str=" abcd ";
print "$str\n";
$str=~s/^\s+|\s$//g;
print "$str\n";

use Data::Dumper;
my %hash;
$hash{1}++;
$hash{1}++;
print Dumper \%hash;

my @arr=("ab", "ab", "bc", "bc",1,1,2,2);

my (%res,@res);
foreach my $r (@arr){
    if(!$res{$r}){
        $res{$r}++;
    }else{
        push(@res,$r);
    }
}

print "@res\n";

open(FH, "<tp") or die "could not find file";

my $count=0;
while (<FH>){
    foreach my $a (split/\s+/, $_){
        if ($a=~/\bfor\b/){
            $count++;
        }
    }
}
print "for : $count\n";

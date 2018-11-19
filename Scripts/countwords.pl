#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;

my %count;
my $file = shift or die "Usage: $0 FILE\n";
open my $fh, '<', $file or die "Could not open '$file' $!";
while (my $line = <$fh>) {
    chomp $line;
    foreach my $str (split /\s+/, $line) {
        $count{$str}++;
    }
}
print Dumper \%count;
foreach my $str (sort keys %count) {
    printf "%-31s %s\n", $str, $count{$str};
}

## Another Method
#open my $fh, '<', 'tp' or die $!;
#my $count = 0;
#while( <$fh> ) {
#    ++$count while m[for]g;
#}
#print "'the' appeared $count times in 'theFile'";

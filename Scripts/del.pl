#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Excel::Writer::XLSX;
use List::Util qw(min max);

my $workbook  = Excel::Writer::XLSX->new( 'simple.xlsx' );
my $worksheet1 = $workbook->add_worksheet();
my $worksheet2 = $workbook->add_worksheet();
my $worksheet3 = $workbook->add_worksheet();
my $file1="result_blocking";
my $file2="result_nonblocking";
open my $result1, "<:encoding(utf8)", $file1 or die "$file1: $!";
open my $result2, "<:encoding(utf8)", $file2 or die "$file2: $!";
 
#  Add and define a format
my $format = $workbook->add_format();
$format->set_bold();
$format->set_color( 'red' );
$format->set_align( 'center' );
 
# Write a formatted and unformatted string, row and column notation.
my $col = 0;
my $globalrow = 0;
 
## Capturing Blocking Values to WorkSheet
my @lines=<$result1>;
my $num = @lines;
my $count=1;
$col = 2;
$globalrow = 4;

my @vals = ("rsaAy2048", "rsaAn2048", "des", "aes128", "aes192", "aes256", "recdes", "recaes128", "recaes256", "recaesgcm128", "recaesgcm256");
foreach my $val (@vals)
{
    @lines = `cat blockingCpu | grep ^$val | cut -f2- -d ' '`;
    &insertCpu(\@lines, $globalrow, $col);
}


sub insertCpu
{
    my $reflines = shift;
    my $row = shift;
    my $col = shift;
    my @lines=@$reflines;
    foreach my $line (@lines){
        chomp $line;
        my @split=split(' ', $line);
        foreach my $aa (@split){
            chomp $aa;
            $worksheet3->write( $row, $col, $aa);
            $col++;
        }
        $col=2;
        $row++;
    }
    $globalrow=$row+1;
}

$workbook->close();


# remove duplicates based on column one elemnets
# awk '!seen[$1]++' a

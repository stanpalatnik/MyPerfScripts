#!/usr/bin/perl
use strict;
use warnings;
use libraryGoogle;

my $worksheet5 = $workbook->add_worksheet("MachineDetails");    ## Machine Details
my $worksheet1 = $workbook->add_worksheet($sheetname{B63TPS});  ## pkpSpeed Blocking Values
my $worksheet2 = $workbook->add_worksheet($sheetname{NB63TPS}); ## pkpSpeed Non Blocking Values
my $worksheet3 = $workbook->add_worksheet($sheetname{B63CPU});  ## CPU Blocking Values
my $worksheet4 = $workbook->add_worksheet($sheetname{NB63CPU}); ## CPU Non Blocking Values
open $result1, "<:encoding(utf8)", $file1 or die "$file1: $!";
open $result2, "<:encoding(utf8)", $file2 or die "$file2: $!";
 
# Write a formatted and unformatted string, row and column notation.
my ($col,$row,$constcol,$count,@lines,$num);
 
## Capturing Blocking Values to WorkSheet
$col = 3; $row = 4; $count=1; $constcol = $col; @lines= <$result1>; $num  = @lines;
&header_ws1($worksheet1, $col);
&header_ws2($worksheet2, $col);
&header_ws3($worksheet3, $col);
&header_ws4($worksheet4, $col);
&header_ws5($worksheet5, 1);

foreach my $line (@lines)
{
    ## RSA 2048, 3072 & RSAServerFull values
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 0, 5, $count, 0, 0);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 5, 10, $count, 1, $constcol);
    ## Record and Plain Crypto Values
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 10, 18, $count, 4, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 18, 26, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 26, 34, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 34, 42, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 42, 50, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 50, 58, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 58, 66, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 66, 74, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 74, 82, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 82, 90, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 90, 98, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 98, 106, $count, 1, $constcol);
    ## Fips Random
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 106, 107, $count, 3, 2);
    ## ECDHFull (P256, P384)
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 107, 108, $count, 3, $constcol);
    ($row,$col)=&insertTPS($worksheet1, $row, $col, $line, 108, 109, $count, 1, $constcol);

    $count++;
}

## Capturing Non Blocking Values to WorkSheet
$col = 3; $row = 4; $count= 1; $constcol = $col; @lines= <$result2>; $num  = @lines;
foreach my $line (@lines)
{
    ## RSA 2048, 3072 values
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 0, 4, $count, 0, 0);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 4, 8, $count, 1, $constcol);
    ## Plain Crypto Values
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 8, 10, $count, 4, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 10, 12, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 12, 14, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 14, 16, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 16, 18, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 18, 20, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 20, 22, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 22, 24, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 24, 26, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 26, 28, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 28, 30, $count, 1, $constcol);
    ($row,$col)=&insertTPS($worksheet2, $row, $col, $line, 30, 32, $count, 1, $constcol);

    $count++;
}

## Inserting CPU Values for Blocking pkpspeed Tests
$col  = 2; $row  = 2; $count= 1; $constcol = $col;
my @vals = ("rsaAy2048", "rsaAn2048", "rsaBy2048", "rsaBn2048", "rsaAy3072", "rsaAn3072", "rsaBy3072", "rsaBn3072", "rsaSE2048", "rsaSE3072", "eccp256", "eccp384", "fipsrandom", "recdes", "recaes128", "recaes256", "recaesgcm128", "recaesgcm256", "aes128", "aes192", "aes256");
foreach my $val (@vals)
{
    @lines = `cat $file3 | grep ^$val | cut -f2- -d ' '`;
    $row+=1 if ($val eq "recdes");
    ($row, $col)=&insertCpu($worksheet3,\@lines, $row, $col);
    $row+=1 if (($val=~/aes/) || ($val=~/des/));
}

## Inserting CPU Values for Non Blocking pkpspeed Tests
$col  = 2; $row  = 2; $count= 1; $constcol = $col;
@vals = ("rsaAy2048", "rsaAn2048", "rsaBy2048", "rsaBn2048", "rsaAy3072", "rsaAn3072", "rsaBy3072", "rsaBn3072", "aes128", "aes256");
foreach my $val (@vals)
{
    @lines = `cat $file4 | grep ^$val | cut -f2- -d ' '`;
    $row+=1 if ($val eq "aes128");
    ($row, $col)=&insertCpu($worksheet4,\@lines, $row, $col);
    $row+=1 if (($val=~/aes/) || ($val=~/des/));
}

$workbook->close();


# remove duplicates based on column one elemnets
# awk '!seen[$1]++' a

#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Excel::Writer::XLSX;
use List::Util qw(min max);

my $workbook  = Excel::Writer::XLSX->new( 'simple.xlsx' );
my $worksheet1 = $workbook->add_worksheet();
my $worksheet2 = $workbook->add_worksheet();
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
my $row = 0;
 
## Capturing Blocking Values to WorkSheet
my @lines=<$result1>;
my $num = @lines;
my $count=1;
$col = 2;
$row = 4;
$worksheet1->write(3,2,"RSA_NONCRT with StaticKey");
$worksheet1->write(3,3,"RSA_NONCRT without StaticKey");
$worksheet1->write(3,4,"RSA_CRT with StaticKey");
$worksheet1->write(3,5,"RSA_CRT without StaticKey");
$worksheet1->write(3,6,"RSAServerFull");

foreach my $line (@lines)
{

    if ($count<=5){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==5);
    $col=2 if ($count==5);
    if ($count>5 && $count <=10){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=4 if ($count==10);
    $col=2 if ($count==10);
    if ($count>10 && $count <=19){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==19);
    $col=2 if ($count==19);
    if ($count>19 && $count <=28){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==28);
    $col=2 if ($count==28);
    if ($count>28 && $count <=37){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==37);
    $col=2 if ($count==37);
    if ($count>37 && $count <=46){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==46);
    $col=2 if ($count==46);
    if ($count>46 && $count <=55){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==55);
    $col=2 if ($count==55);
    if ($count>55 && $count <=64){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==64);
    $col=2 if ($count==64);
    if ($count>64 && $count <=73){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==73);
    $col=2 if ($count==73);
    if ($count>73 && $count <=82){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==82);
    $col=2 if ($count==82);
    if ($count>82 && $count <=91){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==91);
    $col=2 if ($count==91);
    if ($count>91 && $count <=100){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==100);
    $col=2 if ($count==100);
    if ($count>100 && $count <=109){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==109);
    $col=2 if ($count==109);
    if ($count>109 && $count <=118){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=2 if ($count==118);
    $col=2 if ($count==118);
    if ($count>118 && $count <=119){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=2 if ($count==119);
    $col=2 if ($count==119);
    if ($count>119 && $count <=120){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==120);
    $col=2 if ($count==120);
    if ($count>120 && $count <=121){
        $worksheet1->write( $row, $col, $line);
        $col++;
    }

    $count++;
}

## Capturing Non Blocking Values to WorkSheet
@lines=<$result2>;
$num = @lines;
$count=1;
$col = 2;
$row = 4;
foreach my $line (@lines)
{

    if ($count<=4){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==4);
    $col=2 if ($count==4);
    if ($count>4 && $count <=8){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=4 if ($count==8);
    $col=2 if ($count==8);
    if ($count>8 && $count <=11){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==11);
    $col=2 if ($count==11);
    if ($count>11 && $count <=14){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==14);
    $col=2 if ($count==14);
    if ($count>14 && $count <=17){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==17);
    $col=2 if ($count==17);
    if ($count>17 && $count <=20){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==20);
    $col=2 if ($count==20);
    if ($count>20 && $count <=23){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==23);
    $col=2 if ($count==23);
    if ($count>23 && $count <=26){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==26);
    $col=2 if ($count==26);
    if ($count>26 && $count <=29){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==29);
    $col=2 if ($count==29);
    if ($count>29 && $count <=32){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==32);
    $col=2 if ($count==32);
    if ($count>32 && $count <=35){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==35);
    $col=2 if ($count==35);
    if ($count>35 && $count <=38){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==38);
    $col=2 if ($count==38);
    if ($count>38 && $count <=41){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==41);
    $col=2 if ($count==41);
    if ($count>41 && $count <=44){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $count++;
}

$workbook->close();


# remove duplicates based on column one elemnets
# awk '!seen[$1]++' a

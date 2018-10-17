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
$worksheet1->write( $row, $col, 'Hi Excel!', $format );
$worksheet1->write( 1, $col, 'Hi Excel!' );
 
# Write a number and a formula using A1 notation
$worksheet1->write( 'A3', 1.2345 );
$worksheet1->write( 'A4', '=SIN(PI()/4)' );

## Capturing Blocking Values to WorkSheet
my @lines=<$result1>;
my $num = @lines;
my $count=1;
$col = 2;
$row = 4;
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

    if ($count<=5){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

    $row+=1 if ($count==5);
    $col=2 if ($count==5);
    if ($count>5 && $count <=10){
        $worksheet2->write( $row, $col, $line);
        $col++;
    }

}

$workbook->close();


# remove duplicates based on column one elemnets
# awk '!seen[$1]++' a

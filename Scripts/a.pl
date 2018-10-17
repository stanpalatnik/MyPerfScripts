#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Excel::Writer::XLSX;
use List::Util qw(min max);

our (%filenamehash, %globalhash);
my @files = `find scli_* -name \"*.txt\"`;
# remove leading and trailing whitepsces from array
my @newarray = grep(s/\s*$//g, @files);
foreach my $f (@newarray){
    my @n = split('/', $f);
    my $f = $n[1];
    my $ciphertype = "dsa" if($f=~/dsa/);
    $ciphertype = "ecc" if($f=~/ecc/);
    $ciphertype = "rsa" if( !($f=~/dsa/) && !($f=~/ecc/) && !($f=~/ecc_rsa/) );
    $ciphertype = "ecc_rsa" if($f=~/ecc_rsa/);

    my $folder = "scli_apache" if($f=~/apache/i);
    $folder = "scli_nginx" if($f=~/nginx/i);
    $folder = "scli_stunnel" if($f=~/stunnel/i);
    $folder = "scli_sser" if( !($f=~/apache/i) && !($f=~/nginx/i) && !($f=~/stunnel/i) );
    
    my $end1 = "_Nitrox_dsa.txt" if($f=~/dsa/);
    $end1 = "_Nitrox_ecc.txt" if($f=~/ecc/);
    $end1 = "_Nitrox.txt" if( !($f=~/dsa/) && !($f=~/ecc/) && !($f=~/ecc_rsa/) );
    $end1 = "_Nitrox_ecc_rsa.txt" if($f=~/ecc_rsa/);
    
    my $tmp = ($folder eq "scli_sser") ? "_OpenSSL" : "_OpenSource";
    my $end2 = "$tmp"."_dsa.txt" if($f=~/dsa/);
    $end2 = "$tmp"."_ecc.txt" if($f=~/ecc/);
    $end2 = "$tmp.txt" if( !($f=~/dsa/) && !($f=~/ecc/) && !($f=~/ecc_rsa/) );
    $end2 = "$tmp"."_ecc_rsa.txt" if($f=~/ecc_rsa/);
    
    $filenamehash{$folder}{$ciphertype}{cli_open}{ser_nit} = "$f" if (($f=~/Cli_OpenSSL/) && ($f=~/$end1/));
    $filenamehash{$folder}{$ciphertype}{cli_nit}{ser_nit} = "$f" if (($f=~/Cli_Nitrox/) && ($f=~/$end1/));
    $filenamehash{$folder}{$ciphertype}{cli_nit}{ser_open} = "$f" if (($f=~/Cli_Nitrox/) && ($f=~/$end2/));
}

my $workbook  = Excel::Writer::XLSX->new( 'simple.xlsx' );
my @tests = ("scli_sser", "scli_apache", "scli_nginx", "scli_stunnel");
my @ciphers = ("rsa", "dsa", "ecc", "ecc_rsa");
my $sheetcounter = 0;
my $worksheet;

foreach my $test (@tests) {
    $worksheet = $workbook->add_worksheet("$test");
    $worksheet = $workbook->sheets($sheetcounter);
    ## Header listing protocols used in all Sheets
    $worksheet->write(1,0, "ssl3");$worksheet->write(1,1, "tls1");$worksheet->write(1,2, "tls1_1");$worksheet->write(1,3, "tls1_2");
    $worksheet->write(1,5, "ssl3");$worksheet->write(1,6, "tls1");$worksheet->write(1,7, "tls1_1");$worksheet->write(1,8, "tls1_2");
    $worksheet->write(1,10, "ssl3");$worksheet->write(1,11, "tls1");$worksheet->write(1,12, "tls1_1");$worksheet->write(1,13, "tls1_2");
    foreach my $ciph (@ciphers){
        my $fh = $filenamehash{$test}{$ciph}{cli_open}{ser_nit};
        $worksheet->write(0,0, $fh);
        &getcipher($fh) if ($fh);

        $fh = $filenamehash{$test}{$ciph}{cli_nit}{ser_open};
        $worksheet->write(0,5, $fh);
        &getcipher($fh) if ($fh);

        $fh = $filenamehash{$test}{$ciph}{cli_nit}{ser_nit};
        $worksheet->write(0,10, $fh);
        &getcipher($fh) if ($fh);

    }
    $sheetcounter++;
}
$workbook->close;

sub getcipher {
    my $file = shift;
    my @number;
    my $folder = "scli_apache" if($file=~/apache/i);
    $folder = "scli_nginx" if($file=~/nginx/i);
    $folder = "scli_stunnel" if($file=~/stunnel/i);
    $folder = "scli_sser" if( !($file=~/apache/i) && !($file=~/nginx/i) && !($file=~/stunnel/i) );
    my $nfile="$folder/$file";
    
    ## Creating New Log file for Identifying Failures.
    my $script = ($folder eq "scli_sser") ? "processfail_new.pl" : "processfail_nginx.pl";
    `./$script $file`;
    my $log = $file."_pass.log"; $log=~s/.txt//g;
    my $newfile = "$folder/$log";
    
    if (! -e $newfile){
        print "failed to create Log new log\n";
        exit;
    }
    
    `cat $newfile \| grep -- \"\\-FAIL\-  \-FAIL\-\" > /tmp/a`;
    foreach my $proto ("ssl3", "tls1", "tls1_1", "tls1_2"){
        my @resp = `awk '!_[\$0]++' /tmp/a |  grep -w $proto | awk '!seen[\$1]++' | awk '{print \$1}'`;
        my $len = @resp;
        push(@number, $len);
        $worksheet->write(1,0, [ \@resp ]) if ($proto eq "ssl3");
        $worksheet->write(1,1, [ \@resp ]) if ($proto eq "tls1");
        $worksheet->write(1,2, [ \@resp ]) if ($proto eq "tls1_1");
        $worksheet->write(1,3, [ \@resp ]) if ($proto eq "tls1_2");
    }
    $globalhash{maxnum} = max(@number);
}


# remove duplicates based on column one elemnets
# awk '!seen[$1]++' a

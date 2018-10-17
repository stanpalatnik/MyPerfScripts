my $au="./Cfm2Util -p PARTITION_1 singlecmd loginHSM -u AU -s app_user -p user123";
my $cu="./Cfm2Util -p PARTITION_1 singlecmd loginHSM -u CU -s crypto_user -p user123";
my $flag = 0;
open(LOG, ">>log");

my ($Start, $End, $Diff);
$Start = time();
foreach my $i (1..9){
    my @b = `$cu`;
    @b = `$cu genRSAKeyPair -m 2048 -e 65537 -l rsa`; print LOG @b;
    @b = `$cu genDSAKeyPair -m 2048 -l dsa`;          print LOG @b;
    @b = `$cu genECCKeyPair -i 2 -l ecc`;             print LOG @b;
    if (grep(/Firmware log buffer is full/, @b)){
        print "Firmware log buffer is full at loop $i \n";
        exit;
    }
    my @a = `cat /proc/cavium_n3fips/log_overflow`;
    chomp @a;
    if (grep(/1/, @a)){
        print "Overflow bit set at loop $i \n" if ($flag eq 0);
        $flag = 1;
    }

    $End = time();
    $Diff = $End - $Start;
    if ($Diff gt 86400){
        print "Start ".$Start."\n";
        print "End ".$End."\n";
        print "Diff ".$Diff."\n";
        close LOG;
        exit;
    }
}

close LOG;

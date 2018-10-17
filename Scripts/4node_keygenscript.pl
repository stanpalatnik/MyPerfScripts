my ($cmd, @cmdArray);
my $login = "/home/perf/cavClient/2.03-15-tag-30/bin/Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123";
$cmd = "$login genSymKey -l aes -t 31 -s 32 -sess"; push(@cmdArray, $cmd);
$cmd = "$login genECCKeyPair -l ecc -i 2"; push(@cmdArray, $cmd);

foreach my $cmd (@cmdArray){
    print "executing cmd : $cmd\n";
    
    system("$cmd&");
    system("$cmd&");
    system("$cmd&");
    system("$cmd&");

    my $process = `pgrep -l Cfm3Util | awk '{print \$1}'`;
    print "MY PROCESS $process\n";
    chomp $process; print FH "processID: $process\n";
    $count=0;
    while ($process ne ''){
        $process = `pgrep -l Cfm3Util | awk '{print \$1}'`;
        chomp $process; print FH "processID: $process\n";
        if ($count == 16) {
            `kill -9 $process`; sleep 5;
            $process = `pgrep -l Cfm3Util| awk '{print \$1}'`;
            if ($process ne ''){
                print FH "Unable to kill QEMU even after proper shutdown and kill command\n";
                exit;
            }else{
                chomp $process; print FH "processID after Kill Command: $process\n";
            }
        }
        $count++;
        sleep 10;
    }
    print "Exited \n";

    sleep 2;
}

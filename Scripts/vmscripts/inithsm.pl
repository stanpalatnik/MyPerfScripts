use strict;
use warnings;
use Net::SSH;
use Net::SSH::Expect;

#rm -rf cnn35xx-nfbe-kvm-xen-pf/ ; tar -zxf CNN35XX-NFBE-Linux-Driver-KVM-XEN-PF-SDK-2.0-121.tgz; cd cnn35xx-nfbe-kvm-xen-pf/software/ ; make clean; make -s ; make hsm_load partition_name=PARTITION_3; dmesg -c
my ($ssh, @boxes, $pass, $user, $login_output, $output, @output, $to);
if (defined ($ARGV[0])){
@boxes = $ARGV[0];
}else{
@boxes = (
"10.91.207.231",
"10.91.207.178",
"10.91.207.171",
"10.91.208.252",
"10.91.206.3",
"10.91.207.164",
"10.91.205.145",
"10.91.208.61",
"10.91.206.255",
"10.91.206.117",
"10.91.207.67",
"10.91.205.126",
"10.91.208.46",
"10.91.205.190",
"10.91.206.123",
"10.91.207.52",
"10.91.208.53",
"10.91.207.165",
"10.91.208.180",
"10.91.207.96",
"10.91.208.59",
"10.91.206.175",
"10.91.208.82",
"10.91.206.176",
"10.91.206.88",
"10.91.207.201",
"10.91.208.72",
"10.91.206.177",
"10.91.206.99",
"10.91.208.218",
"10.91.206.18",
"10.91.207.19",
);
}

my $i = 1;
my @arr;
my $package = "CNN35XX-NFBE-Linux-Driver-KVM-XEN-PF-SDK-2.0-123.tgz";

foreach my $box (@boxes){
print "box: $box\n";
    my $part = "PARTITION_$i";
    my $cfm2util="/root/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util -p $part singlecmd";
#    my $zero="$cfm2util zeroizeHSM";
#    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$zero\"");
#    my $inithsm="$cfm2util loginHSM -u CO -s cavium -p default initHSM -p so12345 -u user123 -sU crypto_user -sO crypto_officer -a 0 -f hsm_config";
#    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$inithsm\"");
#    my $createau="$cfm2util loginHSM -u CO -s crypto_officer -p so12345 createUser -u AU -s app_user -p user123";
#    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$createau\"");
#    my $au="$cfm2util loginHSM -u AU -s app_user -p user123";
#    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$au\"");
    my $co="$cfm2util loginHSM -u CO -s crypto_officer -p so12345";
    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$co generateKEK\"");
    system("sshpass -p a ssh -o \"StrictHostKeyChecking no\" $box \"$co generatePEK\"");
    $i++;
}

sub prepscript{
my $part = shift;
my $pname = "PARTITION_$part";
my $log="log$part.sh";
`rm -rf $log`;
open(my $fh, ">>$log");
print $fh "#/usr/bin/bash";
print $fh "\n";
print $fh "path=\"/root/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util\"";
print $fh "\n";
print $fh "\$path -p $pname singlecmd zeroizeHSM";
print $fh "\n";
print $fh "\$path -p $pname singlecmd loginHSM -u CO -s cavium -p default initHSM -u user123 -p so12345 -sU crypto_user -sO crypto_officer -a 0 -f hsm_config";
print $fh "\n";
print $fh "\$path -p $pname singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK";
print $fh "\n";
print $fh "\$path -p $pname singlecmd loginHSM -u CO -s crypto_officer -p so12345 generatePEK";
print $fh "\n";
print $fh "\$path -p $pname singlecmd loginHSM -u CO -s crypto_officer -p so12345 createUser -u AU -s app_user -p user123";
print $fh "\n";
close $fh;
}
=pod
$pass="a";
$user="root";

foreach my $box (@boxes){
$ssh = Net::SSH::Expect->new (
                host => "$box",
                password => "$pass",
                user => "$user",
                raw_pty => 1
        );
        undef $login_output;
        eval {
                $login_output = $ssh->login(15);
        };
# If login output is empty try again
        while ($login_output eq "") {
                sleep(2);
                $login_output = $ssh->login(15);
        }
        if ($login_output =~ m/Last login/) {
                print "Login Successful... \n\n";
        } else {
                print "Login has failed! - Please check your username/password and caps lock.  \n\n";
                next;
        }
# RUN COMMANDS AS USER
        print "Running command....\n";
        $ssh->send("ls");
        while ( defined ($output = $ssh->read_line($to)) ) {
# Send output of command to output array for printing when script is complete
                push (@output, "$box: $output");
        }
}
=cut

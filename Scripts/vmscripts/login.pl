use strict;
use warnings;

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
my $daemon="/root/cnn35xx-nfbe-kvm-xen-pf/software/utils/AuditLogDaemon/bin/AuditLogDaemon";
my $conf="/root/cnn35xx-nfbe-kvm-xen-pf/software/utils/AuditLogDaemon/netlink.conf";

foreach my $box (@boxes){
print "box: $box, i : $i\n";
    system("sshpass -p a ssh $box \"init 0\" &");
#    system("sshpass -p a ssh $box \"killall AuditLogDaemon\"");
#    system("sshpass -p a ssh $box \"killall perl\"");
#    system("sshpass -p a ssh $box \"pgrep -l AuditLogDaemon\"");
#    system("sshpass -p a ssh $box \"pgrep -l perl\"");
#    system("sshpass -p a ssh $box \"rm -rf /home/log*\"");
#    system("sshpass -p a ssh $box \"$daemon -f $conf\"&");
#    system("sshpass -p a ssh $box \"perl fillbuffer.pl 100 $i\"&");
#    system("sshpass -p a ssh $box \"pgrep -l AuditLogDaemon\"");
#    system("sshpass -p a ssh $box \"pgrep -l perl\"");
    $i++;
}

#foreach my $box (@boxes){
#print "box: $box, i : $i\n";
#    system("sshpass -p a ssh $box \"ls /home/log*\"");
#}

#!/usr/bin/perl

if ($ARGV[0] eq "h"){
    print "operations permitted zeroize/inithsm/kek/createau/getlog/cert/convert/delete/createpart/finalize\n";
    print "perl $0 all all --> runs zeroize/init/kek/createau/get auditlog/get hcert/get pcert/convert logs to ascii\n";
    print "perl $0 all all --> runs zeroize/init/kek/createau/get auditlog/get hcert/get pcert/convert logs to ascii on all partitions\n";
    print "perl $0 1 all   --> runs zeroize/init/kek/createau/get auditlog/get hcert/get pcert/convert logs to ascii on single partition\n";
    print "perl $0 1 kek   --> executes the specified operation in that partition\n";
    print "perl $0 all kek --> executes the specified operation on all partitions\n";
    exit;
}
open(LOG,">abcd");
my ($nologin,$deflogin,$culogin,$cologin,$aulogin, $createpart, @resp);
my $bindist     = "/home/google/sdk/cnn35xx-nfbe-kvm-xen-pf/software/bindist/";
my $cfm2util    = "/home/google/sdk/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util";
my @array       = (defined $ARGV[0]) ? $ARGV[0] : (1..31);  @array = (1..31) if ($ARGV[0] eq "all");
my $cfm2master  = "/home/google/sdk/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2MasterUtil";
my $masterlogin = "$cfm2master singlecmd loginHSM -u CO -s crypto_officer -p so12345";
my $inithsm     = "initHSM  -p  so12345  -sO  crypto_officer  -u  user123  -sU  crypto_user  -a  0  -f  /etc/cavium/hsm_config";
my @cmdarray    = split(/,/,$ARGV[1]);

foreach my $cmd (@cmdarray){
my $string = ($ARGV[0] eq "all") ? "all partitions" : "partition $ARGV[0]";
print "Running cmd \"$cmd\" on $string\n";

foreach my $part (@array){
    $nologin  = "$cfm2util -p PARTITION singlecmd";
    $deflogin = "$cfm2util -p PARTITION singlecmd loginHSM -u CO -s cavium -p default";
    $culogin  = "$cfm2util -p PARTITION singlecmd loginHSM -u CU -s crypto_user -p user123";
    $cologin  = "$cfm2util -p PARTITION singlecmd loginHSM -u CO -s crypto_officer -p so12345";
    $aulogin  = "$cfm2util -p PARTITION singlecmd loginHSM -u AU -s app_user -p user123";
    $createpart="createPartition  -n  PARTITION -s  1024  -c  1024  -d  2  -f  1  -an  csr  -b  1  -i  INDEX";

    $nologin=~s/PARTITION/PARTITION_$part/;
    $culogin=~s/PARTITION/PARTITION_$part/;
    $cologin=~s/PARTITION/PARTITION_$part/;
    $aulogin=~s/PARTITION/PARTITION_$part/;
    $deflogin=~s/PARTITION/PARTITION_$part/;
    $createpart=~s/PARTITION/PARTITION_$part/;
    $createpart=~s/INDEX/$part/;

    @resp = `$nologin zeroizeHSM`	if (($ARGV[1] eq "zeroize") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$deflogin $inithsm`	if (($ARGV[1] eq "inithsm") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$cologin generateKEK`	if (($ARGV[1] eq "kek") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$cologin createUser  -u  AU  -s  app_user  -p  user123`	if (($ARGV[1] eq "createau") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$aulogin getAuditLogs -l bin_$part -s sign_$part`		if (($ARGV[1] eq "getlog") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$culogin getCert -f pcert_$part -s 16`			if (($ARGV[1] eq "cert") || ($ARGV[1] eq "all"));print LOG @resp;
    @resp = `$culogin getCert -f hcert_$part -s 2`			if (($ARGV[1] eq "cert") || ($ARGV[1] eq "all"));print LOG @resp;
    `$bindist/Cfm2AuditLogUtil -b bin_$part -s sign_$part -pcert pcert_$part -hcert hcert_$part -t log_$part -type 0` if (($ARGV[1] eq "convert") || ($ARGV[1] eq "all"));

    @resp=`$masterlogin $createpart` if ($ARGV[1] eq "createpart");print LOG @resp;
    if ($ARGV[1] eq "delete"){
        @resp = `$masterlogin finalizeLogs -n PARTITION_$part`;print LOG @resp;
        @resp = `$aulogin getAuditLogs -l bin_$part -s sign_$part`;print LOG @resp;
        @resp = `$masterlogin deletePartition -n PARTITION_$part`;print LOG @resp;
    }
    @resp = `$masterlogin finalizeLogs -n PARTITION_$part` if ($ARGV[1] eq "finalize"); print LOG @resp;
}

}

close(LOG);

#!/usr/bin/perl

sub getLogs{
    my $arg1=shift;
    my $partname="PARTITION_$arg1";
    open(FH,">/tmp/$partname");
    my $aulogin="/home/google/sdk/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util -p $partname singlecmd loginHSM -u AU -s app_user -p user123";
    my $getlog="$aulogin getAuditLogs -l bin -s sign";
    foreach my $i (1..99999){
        @resp=`$getlog`;
        print FH "@resp\n";
        if (!(grep(/Number of Logs found 0/,@resp))){
            @resp=`$getlog`;
        }else{
            print "Logs retrieved\n";
            close(FH);
            return;
        }
    }
}

if (($ARGV[0] eq "h") || (@ARGV < 1)){
    print "options zeroize / inithsm / kek / createau / getlog / cert / convert / del / create / finalize\n";
    print "perl list     --> list all available partitions\n";
    print "perl $0 all   --> runs zeroize/init/kek/createau/get auditlog/get hcert/get pcert/convert logs to ascii on all partitions\n";
    print "perl $0 all 1 --> runs zeroize/init/kek/createau/get auditlog/get hcert/get pcert/convert logs to ascii on single partition\n";
    print "perl $0 kek 1 --> executes the specified operation in that partition\n";
    print "perl $0 kek   --> executes the specified operation on all partitions\n";
    exit;
}

my $bindist     = "/home/nikhil/bin/";
my $cfm2master  = "$bindist/Cfm2MasterUtil";
if ($ARGV[0] eq "list"){
    system("$cfm2master singlecmd loginHSM -u CO -s crypto_officer -p so12345 getAllPartitionInfo | grep name");
    exit;
}

my @options=("zeroize","inithsm","kek","createau","getlog","cert","convert","del","create","finalize");
my ($nologin,$deflogin,$culogin,$cologin,$aulogin, $createpart, @resp);
open(LOG,">abcd");

my $data        = "/home/nikhil/data/";
my $cfm2util    = "$bindist/Cfm2Util";
my @array       =  $ARGV[1] || (1..31);
my $masterlogin = "$cfm2master singlecmd loginHSM -u CO -s crypto_officer -p so12345";
my $inithsm     = "initHSM  -p  so12345  -sO  crypto_officer  -u  user123  -sU  crypto_user  -a  0  -f  $data/hsm_config";
my @cmdarray    = split(/,/,$ARGV[0]);

foreach my $cmd (@cmdarray){
my $string = ($ARGV[1]) ? "partition $ARGV[1]." : "all partitions.";
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

    @resp = `$nologin zeroizeHSM`	if (($ARGV[0] eq "zeroize") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = `$deflogin $inithsm`	if (($ARGV[0] eq "inithsm") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = `$cologin generateKEK`	if (($ARGV[0] eq "kek") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = `$cologin createUser  -u  AU  -s  app_user  -p  user123`	if (($ARGV[0] eq "createau") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = &getLogs($part)                                          		if (($ARGV[0] eq "getlog") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = `$culogin getCert -f pcert_$part -s 16`			if (($ARGV[0] eq "cert") || ($ARGV[0] eq "all"));print LOG @resp;
    @resp = `$culogin getCert -f hcert_$part -s 2`			if (($ARGV[0] eq "cert") || ($ARGV[0] eq "all"));print LOG @resp;
    `$bindist/Cfm2AuditLogUtil -b bin_$part -s sign_$part -pcert pcert_$part -hcert hcert_$part -t log_$part -type 0` if (($ARGV[0] eq "convert") || ($ARGV[0] eq "all"));

    if ($ARGV[0] eq "create"){
        @resp=`$masterlogin $createpart`;print LOG @resp;
        @resp = `$nologin zeroizeHSM`;print LOG @resp;
        @resp = `$deflogin $inithsm`;print LOG @resp;
        @resp = `$cologin generateKEK`;print LOG @resp;
        @resp = `$cologin createUser  -u  AU  -s  app_user  -p  user123`;print LOG @resp;
        @resp = `$culogin getCert -f pcert_$part -s 16`;print LOG @resp;
        @resp = `$culogin getCert -f hcert_$part -s 2`;print LOG @resp;
    }
    if ($ARGV[0] eq "del"){
        @resp = `$masterlogin finalizeLogs -n PARTITION_$part`;print LOG @resp;
        if (grep(/zeroized/,@resp = `$nologin getPartitionInfo`)){
            @resp = `$deflogin getAuditLogs -l bin_$part -s sign_$part`;print LOG @resp;
        }else{
            @resp = `$aulogin getAuditLogs -l bin_$part -s sign_$part`;print LOG @resp;
        }
        @resp = `$masterlogin deletePartition -n PARTITION_$part`;print LOG @resp;
    }
    @resp = `$masterlogin finalizeLogs -n PARTITION_$part` if ($ARGV[0] eq "finalize"); print LOG @resp;
}

}

close(LOG);

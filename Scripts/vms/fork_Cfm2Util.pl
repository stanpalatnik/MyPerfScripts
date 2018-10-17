    use strict;
    use warnings;
    use Parallel::ForkManager;
    use Data::Dumper qw(Dumper);
     
    my $forks = shift or die "Usage: $0 N\n";
    my $cfm = "/home/google/sdk/32/build03/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util";
    my $login = "$cfm -p PARTITION_1 singlecmd loginHSM -u CU -s crypto_user -p user123";
     
    my @numbers = map { $_ * 2000000 } reverse 1 .. 10;
    my %results;
     
    print "Forking up to $forks at a time\n";
    my $pm = Parallel::ForkManager->new($forks);
     
    $pm->run_on_finish( sub {
        my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data_structure_reference) = @_;
#        my $q = $data_structure_reference->{input};
#        $results{$q} = $data_structure_reference->{result};
    });
     
    foreach my $q (1..$forks) {
        my $pid = $pm->start and next;
        print "pid: $pid\n";
        my $res = calc();
        $pm->finish(0);
        #$pm->finish(0, { result => $res, input => $q });
    }
    $pm->wait_all_children;
     
    print Dumper \%results;
     
    sub calc {
#        my ($login) = @_;
        foreach my $i (1..10) {
print "i : $i\n";
        `$login genRSAKeyPair -m 2048 -e 65539 -l rsa`;
        }
        return 0;
    }

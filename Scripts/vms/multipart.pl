#!/usr/bin/perl
 
use strict;
use threads;

my $cfm     = "/home/google/sdk/32/build03/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util";

# Define the number of threads
my $num_of_threads = 2;
 
# use the initThreads subroutine to create an array of threads.
my @part1threads = initThreads();
#my @part2threads = initThreads();
 
# Loop through the array:
foreach(@part1threads){
        # Tell each thread to perform our 'doOperation()' subroutine.
        $_ = threads->create(\&doOperation);
print "aa: $_\n";
}
 
#foreach(@part2threads){
#        # Tell each thread to perform our 'doOperation()' subroutine.
#        $_ = threads->create(\&doOperation1);
#}

# This tells the main program to keep running until all threads have finished.
foreach(@part1threads){
    print "part1: $_\n";
    $_->join();
}
 
#foreach(@part2threads){
#    print "part2: $_\n";
#    $_->join();
#}
 
print "\nProgram Done!\nPress Enter to exit\n";
#$a = <>;
 
####################### SUBROUTINES ############################
sub initThreads{
    my @initThreads;
    for(my $i = 1;$i<=$num_of_threads;$i++){
        push(@initThreads,$i);
    }
    return @initThreads;
}
sub doOperation{
    my $login = "$cfm -p PARTITION_1 singlecmd loginHSM -u CU -s crypto_user -p user123";
    # Get the thread id. Allows each thread to be identified.
    my $id = threads->tid();
    my $i = 0;
    while($i < 2){
            $i++;
            `$login genRSAKeyPair -m 2048 -e 65539 -l rsa`;
            sleep 1;
    }
    print "Thread $id done!\n";
    # Exit the thread
    threads->exit();
}
sub doOperation1{
    my $login = "$cfm -p PARTITION_2 singlecmd loginHSM -u CU -s crypto_user -p user123";
    print "$login\n";
    # Get the thread id. Allows each thread to be identified.
    my $id = threads->tid();
    my $i = 0;
    while($i < 2){
            $i++;
            `$login genRSAKeyPair -m 2048 -e 65539 -l rsa`;
            sleep 1;
    }
    print "Thread $id done!\n";
    # Exit the thread
    threads->exit();
}

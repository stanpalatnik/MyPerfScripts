#!/usr/bin/perl
 
use strict;
use threads;

# Define the number of threads
my $num_of_threads = 3;
 
# use the initThreads subroutine to create an array of threads.
my @threads = initThreads();
 
# Loop through the array:
foreach(@threads){
        # Tell each thread to perform our 'doOperation()' subroutine.
        $_ = threads->create(\&doOperation);
}
 
# This tells the main program to keep running until all threads have finished.
foreach(@threads){
    print "abcd: $$_\n";
    $_->join();
}
 
print "\nProgram Done!\nPress Enter to exit";
$a = <>;
 
####################### SUBROUTINES ############################
sub initThreads{
    my @initThreads;
    for(my $i = 1;$i<=$num_of_threads;$i++){
        push(@initThreads,$i);
    }
    return @initThreads;
}
sub doOperation{
    # Get the thread id. Allows each thread to be identified.
    my $id = threads->tid();
    my $i = 0;
    while($i < 2){
            $i++;
            print "$i\n";
            sleep 1;
    }
    print "Thread $id done!\n";
    # Exit the thread
    threads->exit();
}

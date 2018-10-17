#!/usr/bin/perl 

use strict;
use warnings;
use Getopt::Long;
use Net::Telnet;
use Tie::IxHash;
use Carp;
use Cwd;

$SIG{INT} = \&signal_handler;

our %host_info = (
		hsm_name    => 'HSM1',
		ip_addr     => '127.0.0.1',
		user_name   => 'root',
		user_pswd   => 'a',
		prompt      => '/[\$%#>] $/',
		);

our $util_1_log = 'Util_1_handshake_backup.log';

# SDK information
our $sdk            = "/home/akhemka/build_117/cnn35xx-nfbe-kvm-xen-pf/software";
our $Cfm2MasterUtil = "$sdk/bindist/Cfm2MasterUtil";
our $util           = "$sdk/bindist/Cfm2Util";
our $smartcard      = "$sdk/partition_bk_64";
our $certificates   = "/home/akhemka/2.0/Certificates/";
our $time           = 1500;
our $util_prompt    = '/(\s)*Command: (\s)*/i';
our $success_regex = "HSM Return:\\s*SUCCESS";

our $work      = cwd();

# Result file
#our $result_file = "Result_Handshake_backup.log";
our $result_file = "";
our $result_fd;
#our $no_of_iteration_file = "Iterations_handshake_backup.txt";

# Constant global variables
use constant SSH_TIMEOUT => 1800;

# Write to console and log
sub log_msg
{
	my ($str) = @_;

	print $str;
	print $result_fd $str if ($result_fd);
}

sub spwan_pty 
{
	my ($cmd) = @_;
	my ($pid, $tty, $tty_fd);

# Create a new pseudo terminal
	use IO::Pty ();
	my $pty = new IO::Pty or die $!;

# Execute the program in another process
# Child process
	unless ($pid = fork) {
		die "problem spawning program: $!\n" unless defined $pid;

# Disassociate process from existing controlling terminal
		use POSIX ();
		POSIX::setsid
			or die "setsid failed: $!";

# Associate process with new controlling terminal
		$pty->set_raw();
		$tty = $pty->slave();
		$tty_fd = $tty->fileno;
		close $pty;

# Make stdio use the new controlling terminal
		open STDIN, "<&$tty_fd" or die $!;
		open STDOUT, ">&$tty_fd" or die $!;
		open STDERR, ">&STDOUT" or die $!;
		close $tty;

		exec @$cmd
			or die "problem executing $$cmd[0]\n";
	} # end child process  

	$pty;
}

sub open_pty 
{
	my (%args) = @_;

# Prepare command
	my @cmd = ("sshpass" , "-p" , $args{user_pswd} , "ssh" , "-o StrictHostKeyChecking=no ", "-l" , $args{user_name} , $args{ip_addr});

# Start ssh program
	my $pty = &spwan_pty (\@cmd);

# Create a Net::Telnet object to perform I/0 on ssh's tty
	my $ssh = new Net::Telnet (
			-fhopen => $pty,
			-telnetmode => 0,
			-cmd_remove_mode => 1,
			-timeout => SSH_TIMEOUT,
			-output_record_separator => "\r",
			-errmode => sub { print "FAIL\n"; }
			);

# Login to remote host
	$ssh->waitfor ($args{prompt})
		or confess "Problem connecting to host: $ssh->lastline\n";

# logging 
	$ssh->input_log($args{log_file});
	$ssh->cmd("ifconfig");
	$ssh->cmd("date");
	return $ssh;
}

# Check result
sub checkResult
{
	my ($opt, $regex) = @_;
	if (!("@$opt" =~ m/$$regex/ig)) {
# Return FAIL
		return 1;
	}
# Return SUCCESS
	return 0;
}


sub main
{

	my $step;
	my $cmd;
	my $iterations_fd; 
	my @cmd_opt;

	log_msg("\n#### Opened $result_file\n");
	my $local_time = localtime();
	log_msg("#### $local_time\n");

	log_msg("\n#### Launching a ssh session to host\n");
	my $tty = &open_pty (%host_info, log_file => $util_1_log);
	my $tty1 = &open_pty (%host_info, log_file => $util_1_log);
	log_msg("#### Done\n");

	$cmd = $util;
	$tty->cmd (String => $cmd, Prompt => $util_prompt);

	log_msg("\n#### Second section $result_file\n");

	$step = "zeroizeHSM";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "loginHSM -u CO -s cavium -p default";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "initHSM -p so12345 -sO crypto_officer -a 0 -f hsm_config";	
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "loginHSM -u CO -p so12345 -s crypto_officer";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "registerMofnPubKey -u CO -n 1234567 -s crypto_officer -k /home/mykey.pem";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "createUser -u CU -s crypto_user -p user123";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$a = 1;
	while( $a < 9 ) {
		$step = "createUser -u CO -s crypto_officer$a -p so12345";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);
		$a = $a + 1;
	}
	$step = "listUsers";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "logoutHSM";	
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$step = "loginHSM -u CU -s crypto_user -p user123";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$step = "registerMofnPubKey -u CU -n 1234567 -s crypto_user -k /home/mykey.pem";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$step = "logoutHSM";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);
	$a = 1;
	while( $a < 9 ) {
		$step = "loginHSM -u CO -s crypto_officer$a -p so12345";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$step = "registerMofnPubKey -u CO -n 1234567 -s crypto_officer$a -k /home/mykey.pem";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$step = "logoutHSM";
		@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

		$a = $a + 1;
	}

	$step = "loginHSM -u CO -p so12345 -s crypto_officer1";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "setMValue -n 1 -m 2";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "getToken -n 1 -u crypto_officer1 -f /tmp/token";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "openssl dgst -sha256 -sign /home/mykey.pem -out /tmp/token.sign /tmp/token";
	@cmd_opt = $tty1->cmd (String => $step, Prompt => $host_info{prompt}, Timeout => $time);

	$step = "approveToken -af /home/akhemka/2.0/scripts/approveToken/test9.t";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "listTokens";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "backupPartition -m 1 -d /home/akhemka/2.0/scripts/approveToken/backup";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "generateKEK";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "listTokens";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "backupPartition -m 1 -d /home/akhemka/2.0/scripts/approveToken/backup";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$step = "listTokens";
	@cmd_opt = $tty->cmd (String => $step, Prompt => $util_prompt, Timeout => $time);

	$tty->close;
	$tty1->close;



# Return SUCCESS
	return 0;
}

sub signal_handler
{
	die "Caught a signal $!\n\n";
}

&main ();


#!/usr/bin/perl
#
# Author: Jordan Ritter <jpr5@darkridge.com>
# Date: Thu Jul  5 17:08:18 PDT 2001
#
# Input file format:
#
#      Rulename1 file1.gz rule1 bpf_filter1
#      Rulename2 file2.gz rule2 bpf_filter2
#      Rulename3 file3.gz rule3 bpf_filter3
#
# Output:
# 
#      ./ngrepped.Rulename1
#      ./ngrepped.Rulename2
#      ./ngrepped.Rulename3
#
# Considerations:
#
#      1. Not sure how previous script was able to get the pcap filters with spaces using split...
#      2. Don't forget to tweak $max_procs in CONFIG section.
#      3. Blank lines in rule file are bad bad bad.
#      4. Assumes bash.
#  

##########
# CONFIG #
##########

require 5.004;

use POSIX qw(:signal_h);

my($sig_set) = POSIX::SigSet->new(SIGINT);
my($old_sig_set) = POSIX::SigSet->new();
my($max_procs) = 10;

my($rules_file,%rules, @rules);
my($fork_level);
my($loops);

$|++;


#############
# FUNCTIONS #
#############

sub go {
    my($rule_name) = shift @_;
    return unless $rule_name;

    my(%rule) = %{$rules{$rule_name}};

    $fork_level++;

    sigprocmask(SIG_BLOCK, $sig_set, $old_sig_set);    

    my($pipe) = "pipe-$rule-$fork_level";
    my($daddy) = open($pipe, "-|");

    if (not defined $daddy) {

	warn "[$rule_name] fork() error: $!\n";
	sigprocmask(SIG_UNBLOCK, $old_sig_set);
	sleep(1);

    } elsif (not $daddy) {

	my(@args);

        $SIG{INT} = 'IGNORE';
        sigprocmask(SIG_UNBLOCK, $old_sig_set);

	system("zcat $rule{'file'} | " .
               "ngrep -qtI - $rule{'regex'} $rule{'filter'} 2&>1 > " .
               "ngrepped.$rule_name");

	exit;
    
    } else {
	
	sigprocmask(SIG_UNBLOCK, $old_sig_set);

    }

    &go(@_);

    close($pipe);
    print "[$rule_name] finished\n";
}


########
# MAIN #
########

$rules_file = $ARGV[0];

open(RULES, $rules_file) || die "Couldn't open rules file $rules_file: $!.\n";
my(@lines) = <RULES>;
close(RULES);

if (($loops = scalar(@lines)) == 0) { 
    die "Rules file $rules_file empty, exiting.\n"; 
}

%rules = map { chomp(local(@fields) = split / /, $_); 
               $fields[0] => { "file" => $fields[1],
                               "regex" => $fields[2], 
                               "filter" => $fields[3] }; } @lines; 
@rules = keys %rules;

print "Hi, I'm ngrepper, and here we go.\n";

for ( 0 .. int($loops / $max_procs) ) {

    $fork_level = 1;
    @rules_for_this_pass = splice(@rules, 0, $max_procs);

    &go(@rules_for_this_pass);

}

print "Welp, I'm done.\n";

exit;



#!/usr/bin/perl
#
# This program adds a line in the holes database.
# It's supposed to be installed in /etc/qd/fwpuncher
#
# Author: John Bergbom <john.bergbom@gmail.com>

# -----------------
# POD documentation
# -----------------

=head1 NAME

puncher - tool for adding an ip-address into the database of holes
for the firewall

=head1 DESCRIPTION

Expects a properties file residing in /etc/default/fwpuncher.prp having:

=over

=item lockfile=name_of_lock_file

=item hole.db.file=name_of_holes_database

=back

=head1 AUTHOR

John Bergbom <john.bergbom@gmail.com>

=cut

use strict;
use warnings;
# Current directory is no longer in the INC path in perl 5.26, so we need to hardcode
# the directory where the Properties module is located.
use lib '/etc/qd/fwpuncher';
use Properties;
use SynchronizedExecution;
use IPUtils;

# Subroutine for checking the arguments
sub check_arguments {
    my @args = @_;
    #print "@args\n";
    if (@args != 1) {
	print "usage: puncher.pl <ip-address>\n";
	exit;
    }
    return $args[0];
}

sub read_properties {
    my $properties = new Properties();
    $properties->load("/etc/default/fwpuncher.prp");
    #$properties->load("fwpuncher.prp");
    our $lockfile = $properties->getProperty('lockfile');
    our $hole_db = $properties->getProperty('hole.db.file');
    #print "lockfile = $lockfile\n";
    #print "hole_db = $hole_db\n";
}

sub add_ip_to_db {
    my $ip_address = shift;
    #my $lockdir = "/tmp";
    #my $hole_db = "$lockdir/fwpuncher.holes";
    our $lockfile;
    our $hole_db;

    # Set a secure umask for created files
    umask 077;

    # create the holes database if it doesn't exist
    if (! -e $hole_db) {
	open(HOLE_DB, ">$hole_db") || die "$0: can't create hole db $hole_db ($!)\n";
	close HOLE_DB;
    }

    # Add all old rules except for the current ip to a temporary file
    my $ip_match = $ip_address;
    $ip_match =~ s/\./\\./g;
    my $match_str = "^[0-9]+ $ip_match\$";
    open(HOLE_DB, $hole_db) || die "$0: can't open hole db ($!)\n";
    open(HOLE_DB_TMP, ">$hole_db.tmp") || die "$0: can't open hole db ($!)\n";
    while (my $line = <HOLE_DB>) {
	chomp $line;
	#print "2compare \"$line\" to match_str: \"$match_str\":\n";
	if (!($line =~ m/$match_str/)) {
	    print HOLE_DB_TMP $line."\n";
	}
    }

    # Add the current ip to the temporary file and finally replace
    # the original file with the temporary file.
    print HOLE_DB_TMP time." $ip_address";
    close HOLE_DB_TMP;
    close HOLE_DB;
    rename "$hole_db.tmp", $hole_db;
    #print time."\n";
}

# Parse the arguments
my $ip_address = check_arguments(@ARGV);
if (!check_ip_address $ip_address) {
    print "Faulty ip-address: $ip_address\n";
    exit;
}
read_properties;
#print "ip address: $ip_address\n";

# Update the holes database
our $lockfile;
synchronized_execution $lockfile, \&add_ip_to_db, $ip_address;

# Update the firewall
my $res = system "./update-firewall.pl";
if ($res != 0) { die "$0: Couldn't update firewall ($!)\n" }

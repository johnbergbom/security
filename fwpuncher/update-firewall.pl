#!/usr/bin/perl
#
# This program opens up the firewall for the ip-addresses found in the
# holes database and makes sure that too old entries are blocked by the
# firewall. It's supposed to be installed in /etc/qd/fwpuncher
#
# Author: John Bergbom <john.bergbom@gmail.com>

# -----------------
# POD documentation
# -----------------

=head1 NAME

update-firewall - tool for updating the firewall rules

=head1 DESCRIPTION

This program opens up the firewall for the ip-addresses found in the
holes database and makes sure that too old entries are blocked by the
firewall.

Expects a properties file residing in /etc/default/fwpuncher.prp having:

=over

=item lockfile=name_of_lock_file

=item hole.db.file=name_of_holes_database

=item iptables.binary=name_of_iptables_binary

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

sub read_properties {
    my $properties = new Properties();
    $properties->load("/etc/default/fwpuncher.prp");
    our $lockfile = $properties->getProperty('lockfile');
    our $hole_db = $properties->getProperty('hole.db.file');
    our $ip_tables = $properties->getProperty('iptables.binary');
}

sub update_firewall {
    my $ip_address = shift;
    our $lockfile;
    our $hole_db;
    our $ip_tables;

    # Set a secure umask for created files
    umask 077;

    # Clear all old accept rules
    my $res = system "$ip_tables -F FWPUNCHER";
    if ($res != 0) { die "$0: Couldn't clear old firewall rules ($!)\n" }

    # Do nothing if no rules are found
    if (! -e $hole_db) {
	#print "No rules exist.\n";
	return;
    }

    # Filter out holes older than 12 hours
    my $limit = time - 12*60*60;

    # Go through the holes database and open holes in the firewall
    # for still valid ip-addresses, or remove ip-addresses
    # that are too old.
    open(HOLE_DB, $hole_db) || die "$0: can't open hole db ($!)\n";
    open(HOLE_DB_TMP, ">$hole_db.tmp") || die "$0: can't open hole db ($!)\n";
    while (my $line = <HOLE_DB>) {
	chomp $line;
	$line =~ m/^([0-9]+) (.+)$/;
	my $ip_time = $1;
	my $ip_address = $2;
	if ((!defined($ip_time)) || (!defined($ip_address))
	    || (!check_ip_address $ip_address)) {
	    print "Faulty row detected: $line\n";
	} else {
	    if ($ip_time < $limit) {
		#print "Too old, removing: $ip_time, address: $ip_address\n";
	    } else {
		#print "Adding hole for: $ip_time, address: $ip_address\n";
		my $res = system "$ip_tables -A FWPUNCHER -s $ip_address -j ACCEPT";
		if ($res != 0) { die "$0: Couldn't add firewall rule ($!)\n" }
		print HOLE_DB_TMP $line."\n";
	    }
	}
    }
    close HOLE_DB_TMP;
    close HOLE_DB;

    # Finally replace the temporary file with the new file
    rename "$hole_db.tmp", $hole_db;
}

read_properties;
our $lockfile;
synchronized_execution $lockfile, \&update_firewall;

# Perl module containing some utils for handling ip-addresses.
#
# Author: John Bergbom <john.bergbom@gmail.com>

# -----------------
# POD documentation
# -----------------

=head1 NAME

IPUtils - contains utils for handling ip-addresses

=head1 AUTHOR

John Bergbom <john.bergbom@gmail.com>

=cut

use strict;
use warnings;

# Make sure that the ip-address is correct
sub check_ip_address {
    my $ip_address = shift;
    if (!defined($ip_address)) {
	return 0;
    }
    my $correct_address = ($ip_address =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);
    if (!$correct_address) {
	#print "Faulty ip-address: $ip_address\n";
	return 0;
    }
    return 1;
}

return 1;

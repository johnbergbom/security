#!/usr/bin/perl
use Digest::MD5;
#use Digest::MD5 qw(md5_hex);

print "Content-type: text/html\n\n";
my $ip_address = $ENV{'REMOTE_ADDR'};

sub parsedata {
    read(STDIN, $in, $ENV{'CONTENT_LENGTH'});
    @in = split(/&/, $in);

    # All data from a web form will be URL encoded, so we decode
    # it here and put it in a hash.
    foreach $i (0 .. $#in) {
	$in[$i] =~ s/\+/ /g; #decode '+' to ' '
	$in[$i] =~ s/%(..)/pack("c",hex($1))/ge; # decode scandics and such
	($key, $val) = split(/=/,$in[$i],2);
	$in{$key} .= '\0' if (defined($in{$key}));
	$in{$key} .= $val;
    }
}

parsedata;

my $pwd_ok = 0;
if (defined($in{password})) {
    #print "Firewall punched using password $in{password}.\n";
    my $correct_password = "somepassword";
    $md5 = Digest::MD5->new;
    $md5->add($correct_password.$ip_address);
    #$md5->add($correct_password);
    my $expected_md5sum = $md5->hexdigest;
    #print "Expected md5sum: $expected_md5sum, aaa: ".$in{password}."\n";
    if ($expected_md5sum eq $in{password}) {
	$pwd_ok = 1;
	#print "correct password";
	#TODO: add here punching of the firewall
	#my $res = system "touch /tmp/asdasd";
	my $res = system "cd /etc/qd/fwpuncher && sudo ./puncher.pl $ip_address";
	#my $res = system "cd /tmp && touch asdasd3";
	if ($res != 0) { die "$0: Couldn't update firewall ($!)\n" }
    } else {
	#print "wrong password";
    }
}

if ($pwd_ok) {
    print <<HTML;
    <html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>Firewall puncher</title>
	</head>
	<body>
	<h1>Firewall puncher</h1>
	Firewall punched.
	</body>
	</html>
HTML
} else {
    print <<HTML;
    <html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>Firewall puncher</title>
	<script type="text/javascript" src="https://www.sellstar.fi/fwpuncher/webtoolkit.md5.js"></script>
	<script type="text/javascript">
	function calculateMD5() {
	    var pwd = document.getElementById('password');
	    var ip = document.getElementById('ipaddress');
	    pwd.value = MD5(pwd.value+ip.value);
        }
        </script>
	</head>
	<body>
	<h1>Firewall puncher</h1>
	This service is for QD-Tech only. Any unauthorized use is strictly prohibited.
	<br/><br/>
	You are punching the firewall from address $ip_address.
	
	<form method="post" action="fwpuncher.pl" accept-charset="utf-8" onSubmit="calculateMD5();">
	<input type="hidden" id="ipaddress" value="$ip_address"/>
	Enter username:
	<input type="text" id="username" name="username" />
	<br/>
	Enter password:
	<input type="password" id="password" name="password" />
	<input type="submit" name="button" value="Punch" />
	</form>
	</body>
	</html>
HTML
}

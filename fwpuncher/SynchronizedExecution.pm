use strict;
use warnings;
use Properties;
use Fcntl ':flock'; # Import LOCK_* constants
use File::stat;
use POSIX qw(strftime);

# This method executes synchronized
# Parameters
#  - Name of lockfile
#  - Reference to subroutine to execute synchronized.
sub synchronized_execution {
    my $lockfile = shift;
    my $subroutine = shift;
    my @args = @_;

    # If the lock file was created/modified more than an hour ago
    # it was most likely done by some other program that unexpectedly
    # died a long time ago. In this case we can just remove the
    # lock file.
    if (-e $lockfile) {
	my $sb = stat($lockfile);
	my $modified_secs_ago = time - $sb->mtime;
	#printf "File was last modified $modified_secs_ago seconds ago\n";
	if ($modified_secs_ago > 3600) {
	    #print "Removing stale lock file and then sleeping.\n";
	    unlink $lockfile;
	    select(undef, undef, undef, 5); # sleep for five seconds
	}
    }

    # Try to get a file lock
    open(LOCKFILE, ">$lockfile") || die "$0: Couldn't open lock file ($!)\n";
    #print "locking file\n";
    my $i = 0;
    while (1) {
	# use a non-blocking lock
	if (!flock(LOCKFILE, LOCK_EX | LOCK_NB)) {
	    select(undef, undef, undef, 1); # sleep for one second
	} else {
	    last;
	}
	$i++;
	if ($i > 5) {
	    close LOCKFILE;
	    die "$0: Couldn't lock semaphore file after $i attempts ($!)\n";
	}
    }

    # Execute the subroutine safely while holding the lock
    #print "before call\n";
    #$subroutine->();
    $subroutine->(@args);
    #print "after call\n";

    # finally close the lockfile to remove locks
    close LOCKFILE;
    unlink $lockfile;
}

return 1;

package HGLogger;
###############################################################################
# HostGuard Pro - Logging Module
# /usr/local/hostguard/lib/HGLogger.pm
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(strftime);

my $LOG_FILE  = "/var/log/hostguard/daemon.log";
my $LOG_LEVEL = 1;
my $MAX_SIZE  = 10485760; # 10MB

sub init {
    my ($class, %opts) = @_;
    $LOG_FILE  = $opts{file}  if $opts{file};
    $LOG_LEVEL = $opts{level} if defined $opts{level};
    $MAX_SIZE  = $opts{max_size} if $opts{max_size};

    # Ensure log directory exists
    my $dir = $LOG_FILE;
    $dir =~ s|/[^/]+$||;
    unless (-d $dir) {
        system("mkdir", "-p", $dir);
        chmod(0750, $dir);
    }

    return 1;
}

sub error   { _log('ERROR', @_); }
sub log_warn { _log('WARN',  @_); }
sub info    { _log('INFO',  @_); }
sub verbose { _log('VERBOSE', @_) if $LOG_LEVEL >= 2; }
sub debug { _log('DEBUG', @_) if $LOG_LEVEL >= 3; }

sub _log {
    my ($level, $class_or_msg, $msg) = @_;

    # Handle both HGLogger->info("msg") and HGLogger::info("msg")
    if (!defined $msg) {
        $msg = $class_or_msg;
    }

    _rotate_if_needed();

    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $line = "[$ts] [$level] $msg\n";

    open(my $fh, '>>', $LOG_FILE) or return;
    flock($fh, LOCK_EX);
    print $fh $line;
    close($fh);

    # Also print to STDERR if running in foreground debug mode
    if ($LOG_LEVEL >= 3) {
        print STDERR $line;
    }
}

sub _rotate_if_needed {
    return unless -f $LOG_FILE;
    my $size = -s $LOG_FILE;
    return unless $size && $size > $MAX_SIZE;

    # Simple rotation: move to .1, removing old .1
    my $rotated = "$LOG_FILE.1";
    unlink("$rotated.gz") if -f "$rotated.gz";
    rename($rotated, "$rotated.old") if -f $rotated;
    rename($LOG_FILE, $rotated);

    # Compress old log
    if (-f $rotated && -x "/usr/bin/gzip") {
        system("/usr/bin/gzip", $rotated);
    }
    unlink("$rotated.old");
}

# Read the last N lines of the log
sub tail {
    my ($class, $lines) = @_;
    $lines //= 50;
    return () unless -f $LOG_FILE;

    my @result;
    open(my $fh, '<', $LOG_FILE) or return @result;
    my @all = <$fh>;
    close($fh);

    my $start = @all > $lines ? @all - $lines : 0;
    @result = @all[$start .. $#all];
    chomp(@result);
    return @result;
}

1;

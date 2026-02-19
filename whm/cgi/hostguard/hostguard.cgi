#!/usr/bin/perl
#WHMADDON:hostguard:HostGuard Pro
###############################################################################
# HostGuard Pro - WHM Plugin Interface
# /usr/local/cpanel/whostmgr/docroot/cgi/hostguard/hostguard.cgi
#
# Uses cPanel's native Cpanel::Form for parameter parsing and raw HTTP
# headers as required by cpsrvd (cPanel's built-in web server).
# Do NOT use CGI.pm - cpsrvd does not support it reliably.
###############################################################################
use strict;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(strftime);

use lib '/usr/local/hostguard/lib';

# --- WHM Authentication (cPanel native) ---
my $has_cpanel = 0;
eval {
    use lib '/usr/local/cpanel';
    require Cpanel::Form;
    require Whostmgr::ACLS;
    Whostmgr::ACLS::init_acls();
    $has_cpanel = 1;
};

if ($has_cpanel && !Whostmgr::ACLS::hasroot()) {
    print "Content-type: text/html\r\n\r\n";
    print "<h2>Access Denied</h2><p>Root access required for HostGuard Pro.</p>";
    exit;
}

# --- Parse form parameters (cPanel native way, like CSF does) ---
my %FORM;
if ($has_cpanel) {
    %FORM = Cpanel::Form::parseform();
} else {
    %FORM = _parse_form_fallback();
}

# --- Raise rlimits if available (like CSF) ---
eval {
    require Cpanel::Rlimit;
    Cpanel::Rlimit::set_rlimit_to_infinity();
};

# --- Load HostGuard modules with error trapping ---
my ($config, %conf);
my $load_error = '';

eval {
    require HGConfig;
    require HGLogger;
};
if ($@) {
    print "Content-type: text/html\r\n\r\n";
    print "<h2>HostGuard Pro - Module Load Error</h2><pre>$@</pre>";
    print "<p>Check that /usr/local/hostguard/lib/ contains HGConfig.pm and HGLogger.pm</p>";
    exit;
}

eval {
    $config = HGConfig->loadconfig();
    %conf = $config->config();
    HGLogger->init(
        file  => $conf{LOG_FILE} || '/var/log/hostguard/daemon.log',
        level => $conf{LOG_LEVEL} || 1,
    );
};
if ($@) {
    $load_error = "Config load error: $@";
}

my $action   = $FORM{action}  || 'dashboard';
my $do       = $FORM{do}      || '';

###############################################################################
# Rate limiting for POST actions
###############################################################################
my $RATE_FILE = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/whm_ratelimit';

sub check_rate_limit {
    my $now = time();
    my $window = 5;
    if (-f $RATE_FILE) {
        if (open(my $fh, '<', $RATE_FILE)) {
            my $last = <$fh>;
            close($fh);
            chomp $last if $last;
            if ($last && ($now - $last) < $window) {
                return 0;
            }
        }
    }
    if (open(my $fh, '>', $RATE_FILE)) {
        print $fh $now;
        close($fh);
    }
    return 1;
}

###############################################################################
# Process POST actions
###############################################################################
my $message  = '';
my $msg_type = 'info';

if ($ENV{REQUEST_METHOD} && $ENV{REQUEST_METHOD} eq 'POST' && $do) {
    if (!check_rate_limit()) {
        $message = "Rate limited. Please wait a few seconds between actions.";
        $msg_type = 'warning';
    } elsif ($load_error) {
        $message = "Cannot perform actions: $load_error";
        $msg_type = 'danger';
    } else {
        ($message, $msg_type) = process_post_action($do);
        # Refresh config after actions
        eval {
            $config = HGConfig->loadconfig();
            %conf = $config->config();
        };
    }
}

###############################################################################
# Output HTTP header + HTML
###############################################################################
print "Content-type: text/html\r\n\r\n";

print_html_header();
print_nav($action);

if ($load_error) {
    print qq(<div class="alert alert-danger">) . html_escape($load_error) . qq(</div>\n);
}
if ($message) {
    print qq(<div class="alert alert-$msg_type">) . html_escape($message) . qq(</div>\n);
}

# Route to page
if    ($action eq 'dashboard')      { page_dashboard(); }
elsif ($action eq 'config')         { page_config(); }
elsif ($action eq 'allowlist')      { page_list('allow'); }
elsif ($action eq 'denylist')       { page_list('deny'); }
elsif ($action eq 'ignorelist')     { page_list('ignore'); }
elsif ($action eq 'tempblocks')     { page_tempblocks(); }
elsif ($action eq 'services')       { page_services(); }
elsif ($action eq 'logs')           { page_logs(); }
elsif ($action eq 'search_results') { page_search_results(); }
else                                { page_dashboard(); }

print_html_footer();
exit;

###############################################################################
# POST Action Processor
###############################################################################
sub process_post_action {
    my ($post_action) = @_;
    my ($msg, $type) = ('', 'info');

    if ($post_action eq 'firewall_start') {
        my $out = _run_cli('--enable');
        $msg  = "Firewall start command issued.";
        $type = 'success';

    } elsif ($post_action eq 'firewall_stop') {
        my $out = _run_cli('--disable');
        $msg  = "Firewall stopped.";
        $type = 'success';

    } elsif ($post_action eq 'firewall_reload') {
        my $out = _run_cli('--reload');
        $msg  = "Firewall rules reloaded.";
        $type = 'success';

    } elsif ($post_action eq 'daemon_start') {
        system("/usr/local/hostguard/bin/hostguard --start-daemon >/dev/null 2>&1");
        $msg = "Daemon start command issued."; $type = 'success';

    } elsif ($post_action eq 'daemon_stop') {
        system("/usr/local/hostguard/bin/hostguard --stop-daemon >/dev/null 2>&1");
        $msg = "Daemon stop command issued."; $type = 'success';

    } elsif ($post_action eq 'daemon_restart') {
        system("/usr/local/hostguard/bin/hostguard --stop-daemon >/dev/null 2>&1");
        sleep(1);
        system("/usr/local/hostguard/bin/hostguard --start-daemon >/dev/null 2>&1");
        $msg = "Daemon restarted."; $type = 'success';

    } elsif ($post_action eq 'save_config') {
        my $cfg_text = $FORM{config_text} || '';
        if ($conf{RESTRICT_UI} && $conf{RESTRICT_UI} ne "0") {
            $msg = "UI config changes are restricted (RESTRICT_UI=$conf{RESTRICT_UI}). Change via SSH.";
            $type = 'danger';
        } else {
            eval { _save_file("$HGConfig::CONFIG_DIR/hostguard.conf", $cfg_text); };
            $msg  = $@ ? "Error saving config: $@" : "Configuration saved. Reload firewall to apply.";
            $type = $@ ? 'danger' : 'success';
        }

    } elsif ($post_action eq 'save_list') {
        my $list_name = $FORM{list_name} || '';
        my $list_text = $FORM{list_text} || '';
        if ($list_name =~ /^(allow|deny|ignore)$/) {
            eval { _save_file("$HGConfig::CONFIG_DIR/${list_name}.conf", $list_text); };
            $msg  = $@ ? "Error: $@" : ucfirst($list_name) . " list saved. Reload to apply.";
            $type = $@ ? 'danger' : 'success';
        } else {
            $msg = "Invalid list name."; $type = 'danger';
        }

    } elsif ($post_action eq 'quick_allow') {
        my $ip = _sanitize_ip($FORM{ip} || '');
        my $comment = _sanitize_comment($FORM{comment} || 'WHM allow');
        if ($ip) {
            _run_cli('-a', $ip, $comment);
            $msg = "IP $ip added to allowlist."; $type = 'success';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'quick_deny') {
        my $ip = _sanitize_ip($FORM{ip} || '');
        my $comment = _sanitize_comment($FORM{comment} || 'WHM deny');
        if ($ip) {
            _run_cli('-d', $ip, $comment);
            $msg = "IP $ip added to denylist."; $type = 'success';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'unblock') {
        my $ip = _sanitize_ip($FORM{ip} || '');
        if ($ip) {
            _run_cli('-tr', $ip);
            $msg = "Temporary block removed for $ip."; $type = 'success';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'search_ip') {
        my $ip = _sanitize_ip($FORM{ip} || '');
        if ($ip) {
            $action = 'search_results';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }
    }

    return ($msg, $type);
}

# Run CLI command safely (no shell interpolation - list form exec)
sub _run_cli {
    my @args = @_;
    my $cmd = '/usr/local/hostguard/bin/hostguard';
    return '' unless -x $cmd;
    my $pid = open(my $fh, '-|');
    if (!defined $pid) {
        return "Failed to fork: $!";
    }
    if ($pid == 0) {
        open(STDERR, '>&STDOUT');
        exec($cmd, @args) or exit(1);
    }
    my $output = do { local $/; <$fh> };
    close($fh);
    return $output || '';
}

###############################################################################
# Page: Dashboard
###############################################################################
sub page_dashboard {
    my $fw_status = _check_fw_status();
    my $daemon_pid = _get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    my @allow  = _safe_load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    my @deny   = _safe_load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my @blocks = _load_tempblocks();
    my @active = grep { $_->{active} } @blocks;
    my @recent_log = _tail_log(10);

    my $fw_html = $fw_status->{running}
        ? '<span class="status-on">ACTIVE</span>'
        : '<span class="status-off">INACTIVE</span>';
    my $fw_since = $fw_status->{since} ? scalar(localtime($fw_status->{since})) : 'N/A';
    my $dm_html = $daemon_running
        ? '<span class="status-on">RUNNING</span>'
        : '<span class="status-off">STOPPED</span>';
    my $testing = ($conf{TESTING} || '0') eq '1'
        ? '<span class="status-warn">TESTING MODE</span>'
        : 'Disabled';
    my $ipv6 = ($conf{IPV6} || '0') eq '1' ? 'Enabled' : 'Disabled';
    my $ssh_thresh = $conf{LF_SSHD} || '5';
    my $block_dur = _format_duration($conf{LF_TEMP_BLOCK_DURATION} || 3600);
    my $dm_pid_display = $daemon_running ? $daemon_pid : 'N/A';
    my $allow_count = scalar @allow;
    my $deny_count  = scalar @deny;
    my $active_count = scalar @active;

    print <<HTML;
<h2>Dashboard</h2>
<div class="grid">
  <div class="card">
    <h3>Firewall Status</h3>
    <table class="info-table">
      <tr><td>Status:</td><td>$fw_html</td></tr>
      <tr><td>Since:</td><td>$fw_since</td></tr>
      <tr><td>Testing:</td><td>$testing</td></tr>
      <tr><td>IPv6:</td><td>$ipv6</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>Daemon Status</h3>
    <table class="info-table">
      <tr><td>Status:</td><td>$dm_html</td></tr>
      <tr><td>PID:</td><td>$dm_pid_display</td></tr>
      <tr><td>SSH Threshold:</td><td>$ssh_thresh failures</td></tr>
      <tr><td>Block Duration:</td><td>$block_dur</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>IP Lists</h3>
    <table class="info-table">
      <tr><td>Allowlist:</td><td>$allow_count entries</td></tr>
      <tr><td>Denylist:</td><td>$deny_count entries</td></tr>
      <tr><td>Temp Blocks:</td><td>$active_count active</td></tr>
    </table>
  </div>
</div>

<div class="card" style="margin-top:15px;">
  <h3>Quick Actions</h3>
  <form method="post" class="inline-form">
    <input type="hidden" name="action" value="dashboard">
    <label>IP: <input type="text" name="ip" size="20" required></label>
    <label>Note: <input type="text" name="comment" size="20"></label>
    <button type="submit" name="do" value="quick_allow" class="btn btn-success">Allow</button>
    <button type="submit" name="do" value="quick_deny" class="btn btn-danger">Deny</button>
    <button type="submit" name="do" value="search_ip" class="btn btn-info">Search</button>
  </form>
</div>

<div class="card" style="margin-top:15px;">
  <h3>Recent Blocks</h3>
HTML

    if (@active) {
        print '<table class="data-table"><tr><th>IP</th><th>Expires</th><th>TTL</th><th>Reason</th><th>Action</th></tr>';
        my $count = 0;
        for my $b (sort { $b->{expires} <=> $a->{expires} } @active) {
            last if ++$count > 10;
            my $exp = strftime("%Y-%m-%d %H:%M", localtime($b->{expires}));
            my $ttl = _format_duration($b->{ttl});
            my $eip = html_escape($b->{ip});
            my $erea = html_escape($b->{reason});
            print qq(<tr><td>$eip</td><td>$exp</td><td>$ttl</td><td>$erea</td>);
            print qq(<td><form method="post" style="display:inline"><input type="hidden" name="action" value="dashboard"><input type="hidden" name="ip" value="$eip"><button type="submit" name="do" value="unblock" class="btn btn-sm">Unblock</button></form></td></tr>\n);
        }
        print '</table>';
    } else {
        print '<p>No active temporary blocks.</p>';
    }

    print <<HTML;
</div>
<div class="card" style="margin-top:15px;">
  <h3>Recent Log Entries</h3>
  <pre class="log-box">
HTML
    for my $line (@recent_log) {
        print html_escape($line) . "\n";
    }
    print "</pre>\n</div>\n";
}

###############################################################################
# Page: Config Editor
###############################################################################
sub page_config {
    my $cfg_file = "$HGConfig::CONFIG_DIR/hostguard.conf";
    my $content = _read_file($cfg_file);

    unless (defined $content) {
        print "<p class='alert alert-danger'>Cannot read config file: $cfg_file</p>";
        return;
    }

    my $readonly = ($conf{RESTRICT_UI} && $conf{RESTRICT_UI} ne "0") ? 'readonly' : '';
    my $disabled = $readonly ? 'disabled' : '';
    my $escaped = html_escape($content);

    print <<HTML;
<h2>Firewall Configuration</h2>
<div class="card">
  <p>Edit <code>/etc/hostguard/hostguard.conf</code>. After saving, reload the firewall to apply changes.</p>
HTML
    if ($readonly) {
        my $rval = html_escape($conf{RESTRICT_UI});
        print qq(<p class="alert alert-warning">Config editing is restricted (RESTRICT_UI=$rval). Change this setting via SSH.</p>\n);
    }
    print <<HTML;
  <form method="post">
    <input type="hidden" name="action" value="config">
    <textarea name="config_text" rows="35" cols="100" class="code-editor" $readonly>$escaped</textarea>
    <br>
    <button type="submit" name="do" value="save_config" class="btn btn-primary" $disabled>Save Configuration</button>
    <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Firewall</button>
  </form>
</div>
HTML
}

###############################################################################
# Page: IP List Editor (allow/deny/ignore)
###############################################################################
sub page_list {
    my ($list_name) = @_;
    my $file = "$HGConfig::CONFIG_DIR/${list_name}.conf";
    my $display_name = ucfirst($list_name) . "list";

    my $content = _read_file($file);
    unless (defined $content) {
        print "<p class='alert alert-danger'>Cannot read $file</p>";
        return;
    }
    my $escaped = html_escape($content);
    my $ucname = ucfirst($list_name);

    print <<HTML;
<h2>$display_name Editor</h2>
<div class="card">
  <p>Edit <code>$file</code>. One IP/CIDR per line. Comments with # supported. Use <code>Include /path/to/file</code> for external files.</p>

  <form method="post" class="inline-form" style="margin-bottom:10px;">
    <input type="hidden" name="action" value="${list_name}list">
    <label>Quick Add IP: <input type="text" name="ip" size="20"></label>
    <label>Comment: <input type="text" name="comment" size="20"></label>
    <button type="submit" name="do" value="quick_allow" class="btn btn-primary">Add to $ucname</button>
  </form>

  <form method="post">
    <input type="hidden" name="action" value="${list_name}list">
    <input type="hidden" name="list_name" value="$list_name">
    <textarea name="list_text" rows="25" cols="100" class="code-editor">$escaped</textarea>
    <br>
    <button type="submit" name="do" value="save_list" class="btn btn-primary">Save $display_name</button>
    <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Firewall</button>
  </form>
</div>
HTML
}

###############################################################################
# Page: Temporary Blocks
###############################################################################
sub page_tempblocks {
    my @blocks = _load_tempblocks();
    my @active = grep { $_->{active} } @blocks;
    my $active_count = scalar @active;

    print <<HTML;
<h2>Temporary Blocks</h2>
<div class="card">
  <p>Currently active temporary blocks. These expire automatically after their TTL.</p>
HTML

    if (@active) {
        print '<table class="data-table">';
        print '<tr><th>IP Address</th><th>Expires</th><th>TTL</th><th>Reason</th><th>Action</th></tr>';
        for my $b (sort { $a->{expires} <=> $b->{expires} } @active) {
            my $exp = strftime("%Y-%m-%d %H:%M:%S", localtime($b->{expires}));
            my $ttl = _format_duration($b->{ttl});
            my $eip = html_escape($b->{ip});
            my $erea = html_escape($b->{reason});
            print <<HTML;
    <tr>
      <td>$eip</td><td>$exp</td><td>$ttl</td><td>$erea</td>
      <td>
        <form method="post" style="display:inline">
          <input type="hidden" name="action" value="tempblocks">
          <input type="hidden" name="ip" value="$eip">
          <button type="submit" name="do" value="unblock" class="btn btn-sm btn-danger">Unblock</button>
          <button type="submit" name="do" value="quick_allow" class="btn btn-sm btn-success">Allow</button>
        </form>
      </td>
    </tr>
HTML
        }
        print "</table>\n";
        print "<p>Total active blocks: $active_count</p>\n";
    } else {
        print "<p>No active temporary blocks.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# Page: Service Controls
###############################################################################
sub page_services {
    my $fw_status = _check_fw_status();
    my $daemon_pid = _get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    my $fw_html = $fw_status->{running}
        ? '<span class="status-on">ACTIVE</span>'
        : '<span class="status-off">INACTIVE</span>';
    my $dm_html = $daemon_running
        ? "<span class='status-on'>RUNNING (PID $daemon_pid)</span>"
        : '<span class="status-off">STOPPED</span>';

    print <<HTML;
<h2>Service Controls</h2>
<div class="grid">
  <div class="card">
    <h3>Firewall</h3>
    <p>Status: $fw_html</p>
    <form method="post">
      <input type="hidden" name="action" value="services">
      <button type="submit" name="do" value="firewall_start" class="btn btn-success">Start</button>
      <button type="submit" name="do" value="firewall_stop" class="btn btn-danger">Stop</button>
      <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Rules</button>
    </form>
  </div>
  <div class="card">
    <h3>Login Failure Daemon</h3>
    <p>Status: $dm_html</p>
    <form method="post">
      <input type="hidden" name="action" value="services">
      <button type="submit" name="do" value="daemon_start" class="btn btn-success">Start</button>
      <button type="submit" name="do" value="daemon_stop" class="btn btn-danger">Stop</button>
      <button type="submit" name="do" value="daemon_restart" class="btn btn-warning">Restart</button>
    </form>
  </div>
</div>
HTML
}

###############################################################################
# Page: Log Viewer
###############################################################################
sub page_logs {
    my $lines = $FORM{lines} || 100;
    $lines = 100 unless $lines =~ /^\d+$/ && $lines > 0 && $lines <= 1000;
    my @log = _tail_log($lines);

    print <<HTML;
<h2>Daemon Log</h2>
<div class="card">
  <form method="get" class="inline-form" style="margin-bottom:10px;">
    <input type="hidden" name="action" value="logs">
    <label>Lines: <input type="number" name="lines" value="$lines" min="10" max="1000" size="5"></label>
    <button type="submit" class="btn btn-info">Refresh</button>
  </form>
  <pre class="log-box" style="max-height:600px; overflow-y:auto;">
HTML
    for my $line (@log) {
        my $eline = html_escape($line);
        if ($line =~ /\[ERROR\]/) {
            print qq(<span style="color:#dc3545">$eline</span>\n);
        } elsif ($line =~ /\[WARN\]/) {
            print qq(<span style="color:#ffc107">$eline</span>\n);
        } else {
            print "$eline\n";
        }
    }
    print "</pre>\n</div>\n";
}

###############################################################################
# Page: Search Results
###############################################################################
sub page_search_results {
    my $ip = _sanitize_ip($FORM{ip} || '');
    my $eip = html_escape($ip);
    print "<h2>Search Results for $eip</h2>\n";
    print '<div class="card">';

    if ($ip) {
        my $output = _run_cli('-g', $ip);
        if ($output && $output !~ /No entries found/) {
            print "<pre class='log-box'>" . html_escape($output) . "</pre>\n";
        } else {
            print "<p>No entries found for $eip.</p>\n";
        }
    } else {
        print "<p>Invalid IP address.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# HTML Template
###############################################################################
sub print_html_header {
    my $hostname = $ENV{SERVER_NAME} || $ENV{HOSTNAME} || '';
    if (!$hostname) {
        eval { require Sys::Hostname; $hostname = Sys::Hostname::hostname(); };
        $hostname ||= 'server';
    }
    my $ehostname = html_escape($hostname);

    print qq(<!DOCTYPE html>\n<html lang="en">\n<head>\n);
    print qq(<meta charset="UTF-8">\n);
    print qq(<meta name="viewport" content="width=device-width, initial-scale=1.0">\n);
    print qq(<title>HostGuard Pro - $ehostname</title>\n);
    print <<'STYLE';
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; font-size: 14px; }
.container { display: flex; min-height: 100vh; }
.sidebar { width: 220px; background: #1a2332; color: #c8d6e5; padding: 0; flex-shrink: 0; }
.sidebar h1 { font-size: 16px; padding: 18px 15px; background: #0d1520; color: #fff; border-bottom: 2px solid #3498db; }
.sidebar h1 span { color: #3498db; }
.sidebar a { display: block; padding: 10px 15px; color: #c8d6e5; text-decoration: none; border-left: 3px solid transparent; transition: all 0.15s; }
.sidebar a:hover, .sidebar a.active { background: #243447; color: #fff; border-left-color: #3498db; }
.sidebar .nav-section { font-size: 11px; text-transform: uppercase; color: #6b7c93; padding: 15px 15px 5px; letter-spacing: 0.5px; }
.main { flex: 1; padding: 20px 25px; max-width: 1200px; }
.main h2 { color: #1a2332; margin-bottom: 15px; font-size: 22px; }
.card { background: #fff; border-radius: 6px; padding: 18px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.card h3 { color: #1a2332; margin-bottom: 10px; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
.info-table { width: 100%; }
.info-table td { padding: 5px 8px; }
.info-table td:first-child { font-weight: 600; width: 140px; color: #555; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th { background: #f8f9fa; text-align: left; padding: 8px 10px; border-bottom: 2px solid #dee2e6; font-weight: 600; }
.data-table td { padding: 7px 10px; border-bottom: 1px solid #eee; }
.data-table tr:hover { background: #f8f9fa; }
.btn { display: inline-block; padding: 7px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500; text-decoration: none; transition: opacity 0.15s; }
.btn:hover { opacity: 0.85; }
.btn-primary { background: #3498db; color: #fff; }
.btn-success { background: #27ae60; color: #fff; }
.btn-danger { background: #e74c3c; color: #fff; }
.btn-warning { background: #f39c12; color: #fff; }
.btn-info { background: #17a2b8; color: #fff; }
.btn-sm { padding: 3px 10px; font-size: 12px; }
.alert { padding: 12px 16px; border-radius: 4px; margin-bottom: 15px; }
.alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
.alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
.alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
.alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
.code-editor { width: 100%; font-family: "Cascadia Code", "Fira Code", Consolas, monospace; font-size: 13px; border: 1px solid #ddd; border-radius: 4px; padding: 10px; background: #fafafa; line-height: 1.5; tab-size: 4; }
.log-box { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; background: #1a2332; color: #c8d6e5; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.4; max-height: 400px; overflow-y: auto; }
.inline-form { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.inline-form label { display: flex; align-items: center; gap: 5px; }
.inline-form input[type="text"], .inline-form input[type="number"] { padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; }
.status-on { color: #27ae60; font-weight: bold; }
.status-off { color: #e74c3c; font-weight: bold; }
.status-warn { color: #f39c12; font-weight: bold; }
.version { padding: 15px; font-size: 11px; color: #6b7c93; border-top: 1px solid #243447; margin-top: 20px; }
</style>
STYLE
    print qq(</head>\n<body>\n<div class="container">\n);
}

sub print_nav {
    my ($current) = @_;
    my $script = "hostguard.cgi";

    my @nav = (
        ['dashboard',   'Dashboard'],
        ['config',      'Configuration'],
        ['allowlist',   'Allowlist'],
        ['denylist',    'Denylist'],
        ['ignorelist',  'Ignore List'],
        ['tempblocks',  'Temp Blocks'],
        ['services',    'Services'],
        ['logs',        'Log Viewer'],
    );

    print qq(<div class="sidebar">\n);
    print qq(<h1>Host<span>Guard</span> Pro</h1>\n);
    print qq(<div class="nav-section">Management</div>\n);

    for my $item (@nav) {
        my ($key, $label) = @$item;
        my $cls = ($current eq $key) ? ' class="active"' : '';
        print qq(<a href="$script?action=$key"$cls>$label</a>\n);
    }

    my $ver = $HGConfig::VERSION || '1.0.0';
    print qq(<div class="version">v$ver</div>\n);
    print qq(</div>\n);
    print qq(<div class="main">\n);
}

sub print_html_footer {
    print "</div>\n</div>\n</body>\n</html>\n";
}

###############################################################################
# Utility Functions (zero external module dependencies for safety)
###############################################################################

sub html_escape {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    $text =~ s/'/&#39;/g;
    return $text;
}

sub _sanitize_ip {
    my ($ip) = @_;
    return '' unless defined $ip;
    $ip =~ s/\s//g;
    return '' unless $ip =~ /^[0-9a-fA-F.:\/]+$/;
    if ($ip =~ /^[\d.\/]+$/) {
        my ($addr) = split(/\//, $ip);
        return '' unless $addr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        return '' if $1 > 255 || $2 > 255 || $3 > 255 || $4 > 255;
    }
    return $ip;
}

sub _sanitize_comment {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/[^\w\s.,\-()\/]//g;
    return substr($text, 0, 200);
}

sub _read_file {
    my ($file) = @_;
    return undef unless defined $file && -f $file;
    open(my $fh, '<', $file) or return undef;
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
}

sub _save_file {
    my ($file, $content) = @_;
    open(my $fh, '>', $file) or die "Cannot write $file: $!\n";
    flock($fh, LOCK_EX);
    print $fh $content;
    close($fh);
    chmod(0600, $file);
}

sub _check_fw_status {
    my $file = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/firewall.started';
    if (-f $file) {
        my $ts = _read_file($file);
        chomp $ts if defined $ts;
        return { running => 1, since => $ts };
    }
    return { running => 0, since => 0 };
}

sub _get_daemon_pid {
    my $pidfile = "/run/hostguardd.pid";
    return 0 unless -f $pidfile;
    open(my $fh, '<', $pidfile) or return 0;
    my $pid = <$fh>;
    close($fh);
    chomp $pid if $pid;
    return ($pid && $pid =~ /^\d+$/) ? int($pid) : 0;
}

sub _safe_load_iplist {
    my ($file) = @_;
    return () unless -f $file;
    my @entries;
    eval { @entries = HGConfig->load_iplist($file); };
    return @entries;
}

sub _load_tempblocks {
    my $tempfile = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/tempblock.dat';
    my @blocks;
    return @blocks unless -f $tempfile;
    open(my $fh, '<', $tempfile) or return @blocks;
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        my ($ip, $expires, $reason) = split(/\|/, $line, 3);
        next unless $ip && $expires;
        push @blocks, {
            ip      => $ip,
            expires => $expires,
            reason  => $reason || '',
            active  => ($expires > $now ? 1 : 0),
            ttl     => ($expires > $now ? $expires - $now : 0),
        };
    }
    close($fh);
    return @blocks;
}

sub _tail_log {
    my ($num_lines) = @_;
    $num_lines ||= 50;
    my $logfile = $conf{LOG_FILE} || '/var/log/hostguard/daemon.log';
    return ("(log file not found: $logfile)") unless -f $logfile;
    open(my $fh, '<', $logfile) or return ("Cannot read log: $!");
    my @all = <$fh>;
    close($fh);
    my $start = @all > $num_lines ? @all - $num_lines : 0;
    my @result = @all[$start .. $#all];
    chomp(@result);
    return @result;
}

sub _format_duration {
    my ($secs) = @_;
    return '0s' unless $secs;
    $secs = int($secs);
    if ($secs >= 86400) {
        return sprintf("%dd %dh", int($secs/86400), int(($secs%86400)/3600));
    } elsif ($secs >= 3600) {
        return sprintf("%dh %dm", int($secs/3600), int(($secs%3600)/60));
    } elsif ($secs >= 60) {
        return sprintf("%dm %ds", int($secs/60), $secs%60);
    }
    return "${secs}s";
}

# Fallback form parser when Cpanel::Form is not available
sub _parse_form_fallback {
    my %form;
    my $data = '';
    if ($ENV{REQUEST_METHOD} && $ENV{REQUEST_METHOD} eq 'POST') {
        read(STDIN, $data, $ENV{CONTENT_LENGTH} || 0);
    }
    if ($ENV{QUERY_STRING}) {
        $data = $data ? "$data&$ENV{QUERY_STRING}" : $ENV{QUERY_STRING};
    }
    for my $pair (split(/&/, $data)) {
        my ($key, $val) = split(/=/, $pair, 2);
        next unless defined $key;
        $key =~ s/\+/ /g; $key =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
        $val = '' unless defined $val;
        $val =~ s/\+/ /g; $val =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
        $form{$key} = $val;
    }
    return %form;
}

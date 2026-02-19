#!/usr/bin/perl
#WHMADDON:hostguard:HostGuard Pro
###############################################################################
# HostGuard Pro - WHM Plugin Interface
# /usr/local/cpanel/whostmgr/docroot/cgi/hostguard/hostguard.cgi
#
# Provides a full WHM-integrated management interface for the firewall
# and login failure daemon.
###############################################################################
## no critic (RequireUseWarnings, ProhibitExplicitReturnUndef)
use strict;
use CGI qw(:standard);
use CGI::Carp qw(fatalsToBrowser);
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(strftime);
use Sys::Hostname qw(hostname);

use lib '/usr/local/hostguard/lib';
use HGConfig;
use HGFirewall;
use HGLogger;

# WHM authentication
use lib '/usr/local/cpanel';
eval {
    require Whostmgr::ACLS;
    Whostmgr::ACLS::init_acls();
    unless (Whostmgr::ACLS::hasroot()) {
        print header(-type => 'text/html');
        print "<h2>Access Denied</h2><p>Root access required for HostGuard Pro.</p>";
        exit;
    }
};
if ($@) {
    # Fallback: check if running as root
    unless ($> == 0) {
        print header(-type => 'text/html');
        print "<h2>Access Denied</h2><p>Root access required.</p>";
        exit;
    }
}

###############################################################################
# Rate limiting for actions
###############################################################################
my $RATE_FILE = "$HGConfig::DATA_DIR/whm_ratelimit";
sub check_rate_limit {
    my $now = time();
    my $window = 5; # seconds between actions
    if (-f $RATE_FILE) {
        open(my $fh, '<', $RATE_FILE);
        my $last = <$fh>;
        close($fh);
        chomp $last if $last;
        if ($last && ($now - $last) < $window) {
            return 0; # rate limited
        }
    }
    open(my $fh, '>', $RATE_FILE);
    print $fh $now;
    close($fh);
    return 1;
}

###############################################################################
# Parse CGI params
###############################################################################
my $q = CGI->new;
my $action = $q->param('action') // 'dashboard';

# Load config
my $config = HGConfig->loadconfig();
my %conf = $config->config();

HGLogger->init(
    file  => $conf{LOG_FILE} // '/var/log/hostguard/daemon.log',
    level => $conf{LOG_LEVEL} // 1,
);

###############################################################################
# Process POST actions
###############################################################################
my $message = '';
my $msg_type = 'info';

if ($q->request_method() eq 'POST') {
    unless (check_rate_limit()) {
        $message = "Rate limited. Please wait a few seconds between actions.";
        $msg_type = 'warning';
    } else {
        my $post_action = $q->param('do') // '';

        if ($post_action eq 'firewall_start') {
            eval {
                HGFirewall->init($config);
                HGFirewall->start($config);
            };
            $message = $@ ? "Error starting firewall: $@" : "Firewall started successfully.";
            $msg_type = $@ ? 'danger' : 'success';

        } elsif ($post_action eq 'firewall_stop') {
            eval {
                HGFirewall->init($config);
                HGFirewall->stop();
            };
            $message = $@ ? "Error stopping firewall: $@" : "Firewall stopped.";
            $msg_type = $@ ? 'danger' : 'success';

        } elsif ($post_action eq 'firewall_reload') {
            eval {
                my $fresh_config = HGConfig->loadconfig();
                HGFirewall->init($fresh_config);
                HGFirewall->reload($fresh_config);
            };
            $message = $@ ? "Error reloading: $@" : "Firewall rules reloaded.";
            $msg_type = $@ ? 'danger' : 'success';

        } elsif ($post_action eq 'daemon_start') {
            system("/usr/local/hostguard/bin/hostguard --start-daemon >/dev/null 2>&1");
            $message = "Daemon start command issued.";
            $msg_type = 'success';

        } elsif ($post_action eq 'daemon_stop') {
            system("/usr/local/hostguard/bin/hostguard --stop-daemon >/dev/null 2>&1");
            $message = "Daemon stop command issued.";
            $msg_type = 'success';

        } elsif ($post_action eq 'daemon_restart') {
            system("/usr/local/hostguard/bin/hostguard --stop-daemon >/dev/null 2>&1");
            sleep(1);
            system("/usr/local/hostguard/bin/hostguard --start-daemon >/dev/null 2>&1");
            $message = "Daemon restarted.";
            $msg_type = 'success';

        } elsif ($post_action eq 'save_config') {
            my $cfg_text = $q->param('config_text') // '';
            if ($conf{RESTRICT_UI} && $conf{RESTRICT_UI} ne "0") {
                $message = "UI config changes are restricted (RESTRICT_UI=$conf{RESTRICT_UI}).";
                $msg_type = 'danger';
            } else {
                eval { save_config_file($cfg_text); };
                $message = $@ ? "Error saving config: $@" : "Configuration saved. Reload firewall to apply.";
                $msg_type = $@ ? 'danger' : 'success';
            }

        } elsif ($post_action eq 'save_list') {
            my $list_name = $q->param('list_name') // '';
            my $list_text = $q->param('list_text') // '';
            if ($list_name =~ /^(allow|deny|ignore)$/) {
                eval { save_list_file($list_name, $list_text); };
                $message = $@ ? "Error saving: $@" : ucfirst($list_name) . " list saved. Reload firewall to apply.";
                $msg_type = $@ ? 'danger' : 'success';
            }

        } elsif ($post_action eq 'quick_allow') {
            my $ip = sanitize_ip($q->param('ip') // '');
            my $comment = sanitize_comment($q->param('comment') // 'WHM allow');
            if ($ip && HGConfig->valid_ip($ip)) {
                eval {
                    HGFirewall->init($config);
                    HGFirewall->allow($ip, $comment);
                };
                $message = $@ ? "Error: $@" : "IP $ip added to allowlist.";
                $msg_type = $@ ? 'danger' : 'success';
            } else {
                $message = "Invalid IP address.";
                $msg_type = 'danger';
            }

        } elsif ($post_action eq 'quick_deny') {
            my $ip = sanitize_ip($q->param('ip') // '');
            my $comment = sanitize_comment($q->param('comment') // 'WHM deny');
            if ($ip && HGConfig->valid_ip($ip)) {
                eval {
                    HGFirewall->init($config);
                    HGFirewall->permblock($ip, $comment);
                };
                $message = $@ ? "Error: $@" : "IP $ip added to denylist.";
                $msg_type = $@ ? 'danger' : 'success';
            } else {
                $message = "Invalid IP address.";
                $msg_type = 'danger';
            }

        } elsif ($post_action eq 'unblock') {
            my $ip = sanitize_ip($q->param('ip') // '');
            if ($ip && HGConfig->valid_ip($ip)) {
                eval {
                    HGFirewall->init($config);
                    HGFirewall->tempunblock($ip);
                };
                $message = $@ ? "Error: $@" : "Temporary block removed for $ip.";
                $msg_type = $@ ? 'danger' : 'success';
            } else {
                $message = "Invalid IP address.";
                $msg_type = 'danger';
            }

        } elsif ($post_action eq 'search_ip') {
            my $ip = sanitize_ip($q->param('ip') // '');
            if ($ip && HGConfig->valid_ip($ip)) {
                HGFirewall->init($config);
                $action = 'search_results';
            }
        }
    }
    # Refresh config after actions
    $config = HGConfig->loadconfig();
    %conf = $config->config();
}

###############################################################################
# HTML Output
###############################################################################
print header(-type => 'text/html', -charset => 'UTF-8');
print_header();
print_nav($action);

if ($message) {
    print qq(<div class="alert alert-$msg_type">$message</div>\n);
}

if ($action eq 'dashboard') {
    page_dashboard();
} elsif ($action eq 'config') {
    page_config();
} elsif ($action eq 'allowlist') {
    page_list('allow');
} elsif ($action eq 'denylist') {
    page_list('deny');
} elsif ($action eq 'ignorelist') {
    page_list('ignore');
} elsif ($action eq 'tempblocks') {
    page_tempblocks();
} elsif ($action eq 'services') {
    page_services();
} elsif ($action eq 'logs') {
    page_logs();
} elsif ($action eq 'search_results') {
    page_search_results();
} else {
    page_dashboard();
}

print_footer();
exit;

###############################################################################
# Page: Dashboard
###############################################################################

sub page_dashboard {
    HGFirewall->init($config);
    my $st = HGFirewall->status();
    my $daemon_pid = get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    my @deny  = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my @blocks = HGFirewall->list_tempblocks();
    my @active = grep { $_->{active} } @blocks;
    my @recent_log = HGLogger->tail(10);

    my $fw_status = $st->{running} ? '<span class="status-on">ACTIVE</span>' : '<span class="status-off">INACTIVE</span>';
    my $fw_since  = $st->{since} ? scalar(localtime($st->{since})) : 'N/A';
    my $dm_status = $daemon_running ? '<span class="status-on">RUNNING</span>' : '<span class="status-off">STOPPED</span>';
    my $testing   = ($conf{TESTING} // '0') eq '1' ? '<span class="status-warn">TESTING MODE</span>' : 'Disabled';

    print <<HTML;
<h2>Dashboard</h2>
<div class="grid">
  <div class="card">
    <h3>Firewall Status</h3>
    <table class="info-table">
      <tr><td>Status:</td><td>$fw_status</td></tr>
      <tr><td>Since:</td><td>$fw_since</td></tr>
      <tr><td>Testing:</td><td>$testing</td></tr>
      <tr><td>IPv6:</td><td>@{[$conf{IPV6} eq '1' ? 'Enabled' : 'Disabled']}</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>Daemon Status</h3>
    <table class="info-table">
      <tr><td>Status:</td><td>$dm_status</td></tr>
      <tr><td>PID:</td><td>@{[$daemon_running ? $daemon_pid : 'N/A']}</td></tr>
      <tr><td>SSH Threshold:</td><td>$conf{LF_SSHD} failures</td></tr>
      <tr><td>Block Duration:</td><td>@{[format_duration($conf{LF_TEMP_BLOCK_DURATION} // 3600)]}</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>IP Lists</h3>
    <table class="info-table">
      <tr><td>Allowlist:</td><td>@{[scalar @allow]} entries</td></tr>
      <tr><td>Denylist:</td><td>@{[scalar @deny]} entries</td></tr>
      <tr><td>Temp Blocks:</td><td>@{[scalar @active]} active</td></tr>
    </table>
  </div>
</div>

<div class="card" style="margin-top:15px;">
  <h3>Quick Actions</h3>
  <form method="post" class="inline-form">
    <input type="hidden" name="action" value="dashboard">
    <label>IP: <input type="text" name="ip" pattern="[0-9a-fA-F.:/]+" size="20" required></label>
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
            my $ttl = format_duration($b->{ttl});
            my $eip = html_escape($b->{ip});
            my $erea = html_escape($b->{reason});
            print qq(<tr><td>$eip</td><td>$exp</td><td>$ttl</td><td>$erea</td>);
            print qq(<td><form method="post" style="display:inline"><input type="hidden" name="action" value="dashboard"><input type="hidden" name="ip" value="$eip"><button type="submit" name="do" value="unblock" class="btn btn-sm">Unblock</button></form></td></tr>\n);
        }
        print '</table>';
    } else {
        print '<p>No active temporary blocks.</p>';
    }

    # Recent log entries
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
    open(my $fh, '<', $cfg_file) or do {
        print "<p class='error'>Cannot read config file: $!</p>";
        return;
    };
    my $content = do { local $/; <$fh> };
    close($fh);

    my $readonly = ($conf{RESTRICT_UI} && $conf{RESTRICT_UI} ne "0") ? 'readonly' : '';
    my $disabled = $readonly ? 'disabled' : '';

    print <<HTML;
<h2>Firewall Configuration</h2>
<div class="card">
  <p>Edit <code>/etc/hostguard/hostguard.conf</code>. After saving, reload the firewall to apply changes.</p>
HTML
    if ($readonly) {
        print '<p class="alert alert-warning">Config editing is restricted (RESTRICT_UI=' . html_escape($conf{RESTRICT_UI}) . '). Change this setting via SSH.</p>';
    }
    print <<HTML;
  <form method="post">
    <input type="hidden" name="action" value="config">
    <textarea name="config_text" rows="35" cols="100" class="code-editor" $readonly>@{[html_escape($content)]}</textarea>
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

    open(my $fh, '<', $file) or do {
        print "<p class='error'>Cannot read $file: $!</p>";
        return;
    };
    my $content = do { local $/; <$fh> };
    close($fh);

    print <<HTML;
<h2>$display_name Editor</h2>
<div class="card">
  <p>Edit <code>$file</code>. One IP/CIDR per line. Comments with # supported. Use <code>Include /path/to/file</code> for external files.</p>

  <form method="post" class="inline-form" style="margin-bottom:10px;">
    <input type="hidden" name="action" value="${list_name}list">
    <label>Quick Add IP: <input type="text" name="ip" pattern="[0-9a-fA-F.:/]+" size="20"></label>
    <label>Comment: <input type="text" name="comment" size="20"></label>
    <button type="submit" name="do" value="quick_${list_name}" class="btn btn-primary">Add to @{[ucfirst($list_name)]}</button>
  </form>

  <form method="post">
    <input type="hidden" name="action" value="${list_name}list">
    <input type="hidden" name="list_name" value="$list_name">
    <textarea name="list_text" rows="25" cols="100" class="code-editor">@{[html_escape($content)]}</textarea>
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
    my @blocks = HGFirewall->list_tempblocks();
    my @active = grep { $_->{active} } @blocks;

    print <<HTML;
<h2>Temporary Blocks</h2>
<div class="card">
  <p>Currently active temporary blocks. These expire automatically after their TTL.</p>
HTML

    if (@active) {
        print <<HTML;
  <table class="data-table">
    <tr><th>IP Address</th><th>Expires</th><th>TTL</th><th>Reason</th><th>Action</th></tr>
HTML
        for my $b (sort { $a->{expires} <=> $b->{expires} } @active) {
            my $exp = strftime("%Y-%m-%d %H:%M:%S", localtime($b->{expires}));
            my $ttl = format_duration($b->{ttl});
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
        print "<p>Total active blocks: " . scalar(@active) . "</p>\n";
    } else {
        print "<p>No active temporary blocks.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# Page: Service Controls
###############################################################################

sub page_services {
    HGFirewall->init($config);
    my $st = HGFirewall->status();
    my $daemon_pid = get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    print <<HTML;
<h2>Service Controls</h2>
<div class="grid">
  <div class="card">
    <h3>Firewall</h3>
    <p>Status: @{[$st->{running} ? '<span class="status-on">ACTIVE</span>' : '<span class="status-off">INACTIVE</span>']}</p>
    <form method="post">
      <input type="hidden" name="action" value="services">
      <button type="submit" name="do" value="firewall_start" class="btn btn-success">Start</button>
      <button type="submit" name="do" value="firewall_stop" class="btn btn-danger">Stop</button>
      <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Rules</button>
    </form>
  </div>
  <div class="card">
    <h3>Login Failure Daemon</h3>
    <p>Status: @{[$daemon_running ? "<span class='status-on'>RUNNING (PID $daemon_pid)</span>" : '<span class="status-off">STOPPED</span>']}</p>
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
    my $lines = $q->param('lines') // 100;
    $lines = 100 unless $lines =~ /^\d+$/ && $lines > 0 && $lines <= 1000;
    my @log = HGLogger->tail($lines);

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
        # Color-code log levels
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
    my $ip = sanitize_ip($q->param('ip') // '');
    print "<h2>Search Results for ${\html_escape($ip)}</h2>\n";
    print '<div class="card">';

    if ($ip && HGConfig->valid_ip($ip)) {
        my @results = HGFirewall->grep_ip($ip);
        if (@results) {
            print "<table class='data-table'><tr><th>Source</th><th>Details</th></tr>\n";
            for my $r (@results) {
                my $er = html_escape($r);
                print "<tr><td colspan='2'>$er</td></tr>\n";
            }
            print "</table>\n";
        } else {
            print "<p>No entries found for " . html_escape($ip) . ".</p>\n";
        }
    } else {
        print "<p>Invalid IP address.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# HTML Template
###############################################################################

sub print_header {
    my $hostname = hostname() // 'server';
    print <<HTML;
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HostGuard Pro - $hostname</title>
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
.code-editor { width: 100%; font-family: "Cascadia Code", "Fira Code", "Consolas", monospace; font-size: 13px; border: 1px solid #ddd; border-radius: 4px; padding: 10px; background: #fafafa; line-height: 1.5; tab-size: 4; }
.log-box { font-family: "Cascadia Code", "Consolas", monospace; font-size: 12px; background: #1a2332; color: #c8d6e5; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.4; max-height: 400px; overflow-y: auto; }
.inline-form { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.inline-form label { display: flex; align-items: center; gap: 5px; }
.inline-form input[type="text"], .inline-form input[type="number"] { padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; }
.status-on { color: #27ae60; font-weight: bold; }
.status-off { color: #e74c3c; font-weight: bold; }
.status-warn { color: #f39c12; font-weight: bold; }
.version { padding: 15px; font-size: 11px; color: #6b7c93; border-top: 1px solid #243447; margin-top: 20px; }
</style>
</head>
<body>
<div class="container">
HTML
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
        my $active = $current eq $key ? ' class="active"' : '';
        print qq(<a href="$script?action=$key"$active>$label</a>\n);
    }

    print qq(<div class="version">v$HGConfig::VERSION</div>\n);
    print qq(</div>\n);
    print qq(<div class="main">\n);
}

sub print_footer {
    print <<HTML;
</div>
</div>
</body>
</html>
HTML
}

###############################################################################
# Helpers
###############################################################################

sub sanitize_ip {
    my ($ip) = @_;
    return '' unless defined $ip;
    $ip =~ s/\s//g;
    # Only allow IP chars
    return '' unless $ip =~ /^[0-9a-fA-F.:\/]+$/;
    return $ip;
}

sub sanitize_comment {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/[^\w\s.,\-()\/]//g;
    return substr($text, 0, 200);
}

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

sub save_config_file {
    my ($content) = @_;
    my $file = "$HGConfig::CONFIG_DIR/hostguard.conf";
    open(my $fh, '>', $file) or die "Cannot write config: $!\n";
    flock($fh, LOCK_EX);
    print $fh $content;
    close($fh);
    chmod(0600, $file);
}

sub save_list_file {
    my ($name, $content) = @_;
    my $file = "$HGConfig::CONFIG_DIR/${name}.conf";
    open(my $fh, '>', $file) or die "Cannot write $file: $!\n";
    flock($fh, LOCK_EX);
    print $fh $content;
    close($fh);
    chmod(0600, $file);
}

sub get_daemon_pid {
    my $pidfile = "/run/hostguardd.pid";
    return 0 unless -f $pidfile;
    open(my $fh, '<', $pidfile) or return 0;
    my $pid = <$fh>;
    close($fh);
    chomp $pid if $pid;
    return ($pid && $pid =~ /^\d+$/) ? $pid : 0;
}

sub format_duration {
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

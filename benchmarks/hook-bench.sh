#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <release-hook-path> [iterations] [warmup]" >&2
    exit 64
fi

hook=$1
iterations=${2:-100}
warmup=${3:-10}
case "$iterations:$warmup" in
    *[!0-9:]*|:*)
        echo "iterations and warmup must be non-negative integers" >&2
        exit 64
        ;;
esac
if [ "$iterations" -lt 1 ]; then
    echo "iterations must be at least 1" >&2
    exit 64
fi
if [ ! -x "$hook" ]; then
    echo "hook is not executable: $hook" >&2
    exit 66
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
hook_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_dir/crates/delete-denied-hook/Cargo.toml" | head -n 1)
hook_version=${hook_version:-unknown}
commit=$(git -C "$repo_dir" rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
os_name=$(uname -s)
architecture=$(uname -m)
timestamp_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

now_ns() {
    value=$(date '+%s%N')
    case "$value" in
        *%N*)
            if command -v perl >/dev/null 2>&1; then
                perl -MTime::HiRes=time -e 'printf "%.0f\n", time() * 1000000000'
            else
                # This fallback keeps the harness POSIX-only, but only has
                # second resolution on platforms without nanosecond date.
                printf '%s000000000\n' "$(date '+%s')"
            fi
            ;;
        *) printf '%s\n' "$value" ;;
    esac
}

binary_size_bytes() {
    stat -f '%z' "$1" 2>/dev/null || stat -c '%s' "$1"
}

fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/delete-denied-bench.XXXXXX")
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM
root=$fixture_root/root
home=$root/Users/alice
project=$home/Documents/project
cwd=$project/src
mkdir -p "$cwd" "$home/Desktop" "$home/Downloads" "$project/build"
policy=$fixture_root/policy.json
cat >"$policy" <<EOF
{
  "schema_version": 1,
  "variables": {
    "HOME": "$home",
    "USERPROFILE": "$home"
  },
  "protected_paths": [
    {"kind":"filesystem-root","logical":"$root","canonical":"$root","case_sensitive":true},
    {"kind":"users-parent","logical":"$root/Users","canonical":"$root/Users","case_sensitive":true},
    {"kind":"home","logical":"\${HOME}","canonical":"$home","case_sensitive":false},
    {"kind":"documents","logical":"\${HOME}/Documents","canonical":"$home/Documents","case_sensitive":false},
    {"kind":"desktop","logical":"\${HOME}/Desktop","canonical":"$home/Desktop","case_sensitive":false},
    {"kind":"downloads","logical":"\${HOME}/Downloads","canonical":"$home/Downloads","case_sensitive":false}
  ]
}
EOF

safe_input=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"'"$cwd"'","permission_mode":"danger-full-access","tool_input":{"command":"git status"}}')
allow_input=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"'"$cwd"'","permission_mode":"danger-full-access","tool_input":{"command":"rm -rf '"$project"'/build"}}')
deny_input=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"'"$cwd"'","permission_mode":"danger-full-access","tool_input":{"command":"rm -rf '"$home"'"}}')

safe_input_file=$fixture_root/safe.json
allow_input_file=$fixture_root/allow.json
deny_input_file=$fixture_root/deny.json
printf '%s' "$safe_input" >"$safe_input_file"
printf '%s' "$allow_input" >"$allow_input_file"
printf '%s' "$deny_input" >"$deny_input_file"

safe_samples=$fixture_root/safe.ns
allow_samples=$fixture_root/allow.ns
deny_samples=$fixture_root/deny.ns
: >"$safe_samples"
: >"$allow_samples"
: >"$deny_samples"

measure() {
    input=$1
    destination=$2
    start=$(now_ns)
    printf '%s' "$input" | "$hook" --policy "$policy" >/dev/null 2>/dev/null
    status=$?
    end=$(now_ns)
    if [ "$status" -ne 0 ]; then
        echo "hook returned $status while measuring" >&2
        exit 1
    fi
    printf '%s\n' "$((end - start))" >>"$destination"
}

warmup_case() {
    input=$1
    count=0
    while [ "$count" -lt "$warmup" ]; do
        printf '%s' "$input" | "$hook" --policy "$policy" >/dev/null 2>/dev/null
        count=$((count + 1))
    done
}

timer_method='POSIX date fallback (lower-resolution and timer-process biased; do not publish)'
limitations_json='["Peak RSS is a representative macOS /usr/bin/time -l sample, not a per-iteration distribution.","Process startup and stdin parsing are included; filesystem fixtures are temporary and local.","Published measurements require the persistent Perl harness; the POSIX fallback is lower-resolution and timer-process biased."]'

if command -v perl >/dev/null 2>&1; then
    timer_method='persistent Perl Time::HiRes CLOCK_MONOTONIC harness; one hook process per sample'
    raw_samples=$fixture_root/samples.raw
    perl - "$hook" "$policy" "$iterations" "$warmup" "$safe_input_file" "$allow_input_file" "$deny_input_file" >"$raw_samples" <<'PERL'
use strict;
use warnings;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

my ($hook, $policy, $iterations, $warmup, @input_files) = @ARGV;
die "benchmark arguments are incomplete\n" unless @input_files == 3;

sub read_input {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "cannot read fixture $path: $!\n";
    local $/;
    my $input = <$fh> // '';
    close $fh;
    return $input;
}

my @labels = qw(safe suspicious_allow suspicious_deny);
my %inputs;
for my $index (0 .. $#labels) {
    $inputs{$labels[$index]} = read_input($input_files[$index]);
}

sub run_case {
    my ($label, $record) = @_;
    my ($stdin, $stdout, $stderr);
    my $stderr_handle = gensym();
    my $started = clock_gettime(CLOCK_MONOTONIC);
    my $pid = open3($stdin, $stdout, $stderr_handle, $hook, '--policy', $policy);
    print {$stdin} $inputs{$label};
    close $stdin;
    local $/;
    my $output = <$stdout> // '';
    my $error = <$stderr_handle> // '';
    close $stdout;
    close $stderr_handle;
    waitpid($pid, 0);
    my $status = $? >> 8;
    my $elapsed_ns = int((clock_gettime(CLOCK_MONOTONIC) - $started) * 1_000_000_000 + 0.5);
    die "$label hook exit $status\n" if $status != 0;
    die "$label hook wrote stderr\n" if length $error;
    if ($label eq 'suspicious_deny') {
        die "deny output exceeded 4096 bytes\n" if length($output) > 4096;
        die "deny output was not structured JSON\n"
            unless $output =~ /^\{"hookSpecificOutput":/ &&
                   $output =~ /"permissionDecision":"deny"/;
    } elsif (length $output) {
        die "$label allow output was not empty\n";
    }
    print "$label\t$elapsed_ns\n" if $record;
}

for my $label (@labels) {
    run_case($label, 0) for 1 .. $warmup;
}
for (1 .. $iterations) {
    run_case($_, 1) for @labels;
}
PERL
    awk -F '\t' '$1 == "safe" {print $2}' "$raw_samples" >"$safe_samples"
    awk -F '\t' '$1 == "suspicious_allow" {print $2}' "$raw_samples" >"$allow_samples"
    awk -F '\t' '$1 == "suspicious_deny" {print $2}' "$raw_samples" >"$deny_samples"
    for sample_file in "$safe_samples" "$allow_samples" "$deny_samples"; do
        sample_count=$(wc -l <"$sample_file" | tr -d ' ')
        if [ "$sample_count" -ne "$iterations" ]; then
            echo "expected $iterations measured samples in $sample_file, got $sample_count" >&2
            exit 1
        fi
    done
else
    warmup_case "$safe_input"
    warmup_case "$allow_input"
    warmup_case "$deny_input"
    count=0
    while [ "$count" -lt "$iterations" ]; do
        measure "$safe_input" "$safe_samples"
        measure "$allow_input" "$allow_samples"
        measure "$deny_input" "$deny_samples"
        count=$((count + 1))
    done
fi

sort -n "$safe_samples" -o "$safe_samples"
sort -n "$allow_samples" -o "$allow_samples"
sort -n "$deny_samples" -o "$deny_samples"

stat_value() {
    file=$1
    percentile=$2
    count=$(wc -l <"$file" | tr -d ' ')
    p50_rank=$(awk -v n="$count" 'BEGIN { rank = int(n * 0.5 + 0.999999); if (rank < 1) rank = 1; print rank }')
    p95_rank=$(awk -v n="$count" -v p="$percentile" 'BEGIN { rank = int(n * p + 0.999999); if (rank < 1) rank = 1; print rank }')
    p50_value=$(awk -v rank="$p50_rank" 'NR == rank { print; exit }' "$file")
    p95_value=$(awk -v rank="$p95_rank" 'NR == rank { print; exit }' "$file")
    max_value=$(tail -n 1 "$file")
    printf '{"p50_ns":%s,"p95_ns":%s,"max_ns":%s}' \
        "$p50_value" "$p95_value" "$max_value"
}

peak_rss_bytes=null
if command -v /usr/bin/time >/dev/null 2>&1; then
    rss_log=$fixture_root/rss.log
    # shellcheck disable=SC2016
    /usr/bin/time -l sh -c 'printf "%s" "$1" | "$2" --policy "$3" >/dev/null 2>/dev/null' sh "$deny_input" "$hook" "$policy" 2>"$rss_log" || true
    rss=$(sed -n 's/^[[:space:]]*\([0-9][0-9]*\)[[:space:]]*maximum resident set size.*/\1/p' "$rss_log" | tail -n 1)
    case "$rss" in
        ''|*[!0-9]*) ;;
        *) peak_rss_bytes=$rss ;;
    esac
fi

printf '{"os":"%s","architecture":"%s","hook_version":"%s","commit":"%s","build_profile":"release","timestamp_utc":"%s","iterations":%s,"warmup":%s,"binary_size_bytes":%s,"safe":%s,"suspicious_allow":%s,"suspicious_deny":%s,"peak_rss_bytes":%s,"method":"%s","limitations":%s}\n' \
    "$(printf '%s' "$os_name" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$(printf '%s' "$architecture" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$(printf '%s' "$hook_version" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$(printf '%s' "$commit" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$timestamp_utc" \
    "$iterations" "$warmup" "$(binary_size_bytes "$hook")" \
    "$(stat_value "$safe_samples" 0.95)" \
    "$(stat_value "$allow_samples" 0.95)" \
    "$(stat_value "$deny_samples" 0.95)" \
    "$peak_rss_bytes" \
    "$(printf '%s' "$timer_method" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$limitations_json"

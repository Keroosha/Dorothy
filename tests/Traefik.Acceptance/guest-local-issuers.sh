#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'Usage: guest-local-issuers.sh check STATIC_JSON [keroosha-traefik.service] | check-env-file DNS_ENV_FILE\n' >&2
    exit 2
}
fail() {
    printf 'local issuer guard: %s\n' "$1" >&2
    exit 1
}
validate_dns_environment_file() {
    local environment_file=$1
    [[ -f $environment_file && ! -L $environment_file ]] || fail 'DNS environment file is not a regular file'
    if ! perl - "$environment_file" >/dev/null 2>&1 <<'PERL'
use strict;
use warnings;
my %allowed = map { $_ => 1 } qw(
    DNSUPDATE_NAMESERVER DNSUPDATE_DNS_TIMEOUT DNSUPDATE_ZONES DNSUPDATE_TTL
    DNSUPDATE_PROPAGATION_TIMEOUT DNSUPDATE_POLLING_INTERVAL DNSUPDATE_SEQUENCE_INTERVAL
    DNSUPDATE_TSIG_KEY DNSUPDATE_TSIG_SECRET DNSUPDATE_TSIG_ALGORITHM
);
open my $fh, '<:raw', $ARGV[0] or die "invalid environment file\n";
my %seen;
while (my $line = <$fh>) {
    chomp $line;
    $line =~ s/\r$//;
    next if $line =~ /^[[:space:]]*(?:#|$)/;
    my ($name, $value) = $line =~ /^([A-Z][A-Z0-9_]*)="((?:[^"\\]|\\.)*)"$/;
    die "invalid environment file\n" unless defined $name && $allowed{$name} && !$seen{$name}++;
    die "nonlocal DNS nameserver\n" if $name eq 'DNSUPDATE_NAMESERVER' && $value ne '127.0.0.1:1053';
    die "nonlocal DNS zone\n" if $name eq 'DNSUPDATE_ZONES' && $value ne 'acceptance.test';
}
close $fh or die "invalid environment file\n";
die "missing local DNS settings\n"
    unless $seen{DNSUPDATE_NAMESERVER} && $seen{DNSUPDATE_ZONES};
PERL
    then
        fail 'Traefik DNS credentials must be the local fixture DNSUPDATE environment only'
    fi
}
if [[ $# == 2 && $1 == check-env-file ]]; then
    command -v perl >/dev/null 2>&1 || fail 'Perl is unavailable'
    command -v realpath >/dev/null 2>&1 || fail 'realpath is unavailable'
    [[ -f $2 && ! -L $2 ]] || fail 'DNS environment file is not a regular file'
    [[ $(realpath -e -- "$2") == "$2" ]] || fail 'DNS environment file path is not canonical'
    validate_dns_environment_file "$2"
    printf 'local fixture DNS environment accepted\n'
    exit 0
fi
[[ $# == 2 || $# == 3 ]] || usage
[[ $1 == check ]] || usage
static_file=$2
target_unit=${3:-}

for command in jq perl realpath; do
    command -v "$command" >/dev/null 2>&1 || fail "required local command is missing: $command"
done
[[ -f "$static_file" && ! -L "$static_file" ]] || fail 'static configuration is not a regular non-symlink file'
canonical_file=$(realpath -e -- "$static_file") || fail 'static configuration cannot be resolved'
[[ $canonical_file == "$static_file" ]] || fail 'static configuration path is not canonical'

# Traefik emits the managed static file as JSON (which is also valid YAML). Requiring JSON here
# keeps this gate on the exact persisted representation and rejects YAML anchors/aliases.
LC_ALL=C jq -e -s 'length == 1 and (.[0] | type == "object")' "$static_file" >/dev/null 2>&1 \
    || fail 'static configuration must be one JSON object'

# jq validates JSON syntax but object construction can hide duplicate keys. Walk string tokens
# before decoding so exact duplicate names (including escaped spellings) cannot shadow a check.
if ! perl - "$static_file" >/dev/null 2>&1 <<'PERL'
use strict;
use warnings;
use JSON::PP ();

my $path = shift @ARGV;
open my $fh, '<:raw', $path or die "invalid JSON\n";
local $/;
my $json = <$fh>;
close $fh or die "invalid JSON\n";
my $length = length($json);
my $offset = 0;
my @stack;
my $root_state = 'value';

sub string_value {
    my ($json_ref, $length_ref, $offset_ref) = @_;
    my $start = $$offset_ref;
    ++$$offset_ref;
    while ($$offset_ref < $$length_ref) {
        my $byte = substr($$json_ref, $$offset_ref, 1);
        if ($byte eq '\\') {
            $$offset_ref += 2;
            next;
        }
        if ($byte eq '"') {
            ++$$offset_ref;
            my $token = substr($$json_ref, $start, $$offset_ref - $start);
            my $decoded = JSON::PP::decode_json('[' . $token . ']');
            return $decoded->[0];
        }
        ++$$offset_ref;
    }
    die "invalid JSON\n";
}

sub consume_value {
    my ($json_ref, $length_ref, $offset_ref, $stack_ref) = @_;
    my $byte = substr($$json_ref, $$offset_ref, 1);
    if ($byte eq '{' || $byte eq '[') {
        ++$$offset_ref;
        push @$stack_ref, $byte eq '{'
            ? { type => 'object', state => 'key', keys => {} }
            : { type => 'array', state => 'value' };
        return;
    }
    if ($byte eq '"') {
        string_value($json_ref, $length_ref, $offset_ref);
        return;
    }
    while ($$offset_ref < $$length_ref) {
        my $next = substr($$json_ref, $$offset_ref, 1);
        last if $next =~ /[\x20\x09\x0a\x0d,}\]]/;
        ++$$offset_ref;
    }
}

while ($offset < $length) {
    my $byte = substr($json, $offset, 1);
    if ($byte =~ /[\x20\x09\x0a\x0d]/) {
        ++$offset;
        next;
    }
    if (!@stack) {
        if ($root_state eq 'value') {
            $root_state = 'end';
            consume_value(\$json, \$length, \$offset, \@stack);
        } else {
            ++$offset;
        }
        next;
    }
    my $frame = $stack[-1];
    if ($frame->{type} eq 'object') {
        if ($frame->{state} eq 'key') {
            if ($byte eq '}') {
                ++$offset;
                pop @stack;
            } elsif ($byte eq '"') {
                my $key = string_value(\$json, \$length, \$offset);
                die "duplicate JSON key\n" if exists $frame->{keys}{$key};
                $frame->{keys}{$key} = 1;
                $frame->{state} = 'colon';
            } else {
                ++$offset;
            }
        } elsif ($frame->{state} eq 'colon') {
            $frame->{state} = 'value' if $byte eq ':';
            ++$offset;
        } elsif ($frame->{state} eq 'value') {
            $frame->{state} = 'end';
            consume_value(\$json, \$length, \$offset, \@stack);
        } elsif ($frame->{state} eq 'end') {
            if ($byte eq ',') {
                $frame->{state} = 'key';
            } elsif ($byte eq '}') {
                pop @stack;
            }
            ++$offset;
        }
    } else {
        if ($frame->{state} eq 'value') {
            if ($byte eq ']') {
                ++$offset;
                pop @stack;
            } else {
                $frame->{state} = 'end';
                consume_value(\$json, \$length, \$offset, \@stack);
            }
        } elsif ($frame->{state} eq 'end') {
            if ($byte eq ',') {
                $frame->{state} = 'value';
            } elsif ($byte eq ']') {
                pop @stack;
            }
            ++$offset;
        }
    }
}

my $root = JSON::PP::decode_json($json);
die "invalid root\n" unless ref($root) eq 'HASH';

sub normalized_key {
    my ($key) = @_;
    $key =~ s/[-_.]//g;
    return lc($key);
}
sub inspect_paths {
    my ($value, $path_ref) = @_;
    return unless ref($value);
    if (ref($value) eq 'HASH') {
        for my $key (keys %$value) {
            my $kind = normalized_key($key);
            if ($kind eq 'certificatesresolvers' || $kind eq 'entrypoints') {
                my $expected = $kind eq 'entrypoints' ? 'entryPoints' : 'certificatesResolvers';
                die "misplaced or aliased static map\n"
                    unless @$path_ref == 0 && $key eq $expected;
            } elsif ($kind eq 'acme') {
                die "misplaced or aliased acme\n"
                    unless @$path_ref == 2
                        && $path_ref->[0] eq 'certificatesResolvers'
                        && $key eq 'acme';
            } elsif ($kind eq 'caserver') {
                die "misplaced or aliased caServer\n"
                    unless @$path_ref == 3
                        && $path_ref->[0] eq 'certificatesResolvers'
                        && $path_ref->[2] eq 'acme'
                        && $key eq 'caServer';
            } elsif ($kind eq 'dnschallenge' || $kind eq 'httpchallenge' || $kind eq 'tlschallenge') {
                my %exact = (dnschallenge => 'dnsChallenge', httpchallenge => 'httpChallenge', tlschallenge => 'tlsChallenge');
                die "misplaced or aliased ACME challenge\n"
                    unless @$path_ref == 3
                        && $path_ref->[0] eq 'certificatesResolvers'
                        && $path_ref->[2] eq 'acme'
                        && $key eq $exact{$kind};
            } elsif ($kind eq 'provider' || $kind eq 'resolvers') {
                my %exact = (provider => 'provider', resolvers => 'resolvers');
                die "misplaced or aliased DNS challenge field\n"
                    unless @$path_ref == 4
                        && $path_ref->[0] eq 'certificatesResolvers'
                        && $path_ref->[2] eq 'acme'
                        && $path_ref->[3] eq 'dnsChallenge'
                        && $key eq $exact{$kind};
            } elsif ($kind eq 'entrypoint' && @$path_ref == 4
                     && $path_ref->[0] eq 'certificatesResolvers'
                     && $path_ref->[2] eq 'acme'
                     && $path_ref->[3] eq 'httpChallenge') {
                die "aliased HTTP challenge field\n" unless $key eq 'entryPoint';
            } elsif ($kind eq 'address' && @$path_ref == 2 && $path_ref->[0] eq 'entryPoints') {
                die "aliased entryPoint address\n" unless $key eq 'address';
            }
            inspect_paths($value->{$key}, [ @$path_ref, $key ]);
        }
    } elsif (ref($value) eq 'ARRAY') {
        inspect_paths($_, [ @$path_ref ]) for @$value;
    }
}
inspect_paths($root, []);

if (exists $root->{certificatesResolvers}) {
    my $resolvers = $root->{certificatesResolvers};
    die "invalid resolver map\n" unless ref($resolvers) eq 'HASH';
    if (keys %$resolvers) {
    my $entry_points = $root->{entryPoints};
    die "invalid local entryPoint map\n" unless ref($entry_points) eq 'HASH';
    my %known = map { $_ => 1 } qw(keroosha-admin websecure front secure mtls tcp udp udp-other http01 tlsalpn proxy-front sni-proof rollback-collision);
    for my $name (keys %$entry_points) {
        die "unknown fixture entryPoint\n" unless $known{$name};
        my $entry = $entry_points->{$name};
        die "invalid fixture entryPoint\n" unless ref($entry) eq 'HASH';
        my $address = $entry->{address} // '';
        # Historical numeric traffic binds are part of the migration proof. They are
        # not ACME challenge binds and have no host forward through the sealed VM.
        next if $name eq 'websecure' && $address =~ /\A:443(?:\/tcp)?\z/;
        die "nonlocal fixture entryPoint\n" unless !ref($address)
            && $address =~ /\A(?:127(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}|\[::1\]):([1-9][0-9]{0,4})(?:\/(?:tcp|udp))?\z/
            && $1 <= 65535;
    }
    for my $name (keys %$resolvers) {
        my $resolver = $resolvers->{$name};
        die "invalid resolver\n" unless ref($resolver) eq 'HASH';
        die "unsupported resolver field\n" if grep { $_ ne 'acme' } keys %$resolver;
        die "resolver has no ACME issuer\n" unless exists $resolver->{acme};
        my $acme = $resolver->{acme};
        die "invalid ACME issuer\n" unless ref($acme) eq 'HASH';
        die "ACME issuer has no explicit caServer\n" unless exists $acme->{caServer};
        my $server = $acme->{caServer};
        die "unknown ACME issuer\n"
            unless defined($server) && !ref($server)
                && ($server eq 'https://localhost:14000/dir'
                    || $server eq 'https://localhost:14001/dir');
        my @challenges = grep { exists $acme->{$_} } qw(dnsChallenge httpChallenge tlsChallenge);
        die "resolver must select exactly one local ACME challenge\n" unless @challenges == 1;
        if ($challenges[0] eq 'dnsChallenge') {
            my $challenge = $acme->{dnsChallenge};
            die "invalid DNS challenge\n" unless ref($challenge) eq 'HASH';
            my %allowed = map { $_ => 1 } qw(provider resolvers propagation delayBeforeCheck disablePropagationCheck);
            die "unsupported DNS challenge field\n" if grep { !$allowed{$_} } keys %$challenge;
            die "DNS challenge must use dnsupdate\n"
                unless defined($challenge->{provider}) && !ref($challenge->{provider})
                    && $challenge->{provider} eq 'dnsupdate';
            my $nameservers = $challenge->{resolvers};
            die "DNS challenge must use only the local fixture resolver\n"
                unless ref($nameservers) eq 'ARRAY' && @$nameservers == 1
                    && defined($nameservers->[0]) && !ref($nameservers->[0])
                    && $nameservers->[0] eq '127.0.0.1:1053';
        } elsif ($challenges[0] eq 'httpChallenge') {
            my $challenge = $acme->{httpChallenge};
            die "invalid HTTP challenge\n" unless ref($challenge) eq 'HASH';
            my %allowed = map { $_ => 1 } qw(entryPoint delay);
            die "unsupported HTTP challenge field\n" if grep { !$allowed{$_} } keys %$challenge;
            die "HTTP challenge must use the local http01 listener\n"
                unless defined($challenge->{entryPoint}) && !ref($challenge->{entryPoint})
                    && $challenge->{entryPoint} eq 'http01'
                    && (($entry_points->{http01}{address} // '') eq '127.0.0.1:5002'
                        || ($entry_points->{http01}{address} // '') eq '127.0.0.1:5002/tcp');
        } else {
            my $challenge = $acme->{tlsChallenge};
            die "invalid TLS-ALPN challenge\n" unless ref($challenge) eq 'HASH';
            my %allowed = map { $_ => 1 } qw(delay);
            die "unsupported TLS-ALPN challenge field\n" if grep { !$allowed{$_} } keys %$challenge;
            die "TLS-ALPN challenge has no local fixture listener\n"
                unless (($entry_points->{tlsalpn}{address} // '') eq '127.0.0.1:5001'
                    || ($entry_points->{tlsalpn}{address} // '') eq '127.0.0.1:5001/tcp');
        }
    }
    }
}

PERL
then
    fail 'static configuration contains duplicate keys, aliases, an unknown issuer, or an incomplete resolver'
fi
needs_dns=$(LC_ALL=C jq -r 'any((.certificatesResolvers // {})[]; .acme | has("dnsChallenge"))' "$static_file") \
    || fail 'cannot determine whether local DNS credentials are required'

# Do not allow inherited Traefik/DNS overrides or proxy routing to influence the guard or a daemon.
check_env_name() {
    local upper=${1^^}
    if [[ $upper == TRAEFIK_* || $upper == DNSUPDATE_* || $upper == *PROXY* ]]; then
        fail 'ambient Traefik/DNS overrides and proxy variables are forbidden'
    fi
    return 0
}
while IFS= read -r -d '' entry; do
    check_env_name "${entry%%=*}"
done < <(env -0)

if [[ -n $target_unit ]]; then
    [[ $target_unit == keroosha-traefik.service && $static_file == /etc/keroosha-iac/traefik/static.yml ]] \
        || fail 'systemd guard target or static file is not the managed Traefik service'
    command -v systemctl >/dev/null 2>&1 || fail 'systemctl is unavailable'

    manager_environment=$(systemctl show-environment) || fail 'cannot inspect systemd manager environment'
    while IFS= read -r line; do
        [[ $line == *=* ]] || continue
        check_env_name "${line%%=*}"
    done <<< "$manager_environment"

    fragment=$(systemctl show --property=FragmentPath --value "$target_unit") \
        || fail 'cannot inspect the managed Traefik unit'
    [[ $fragment == /etc/systemd/system/keroosha-traefik.service && -f $fragment && ! -L $fragment ]] \
        || fail 'managed Traefik unit is missing or not the expected unit file'
    declared_exec=$(grep -E '^ExecStart=' "$fragment" || true)
    [[ $declared_exec == 'ExecStart=/usr/local/libexec/keroosha-iac/traefik/3.7.16/traefik --configFile=/etc/keroosha-iac/traefik/static.yml' ]] \
        || fail 'managed Traefik unit does not execute the pinned binary with the checked static file'
    dropins=$(systemctl show --property=DropInPaths --value "$target_unit") \
        || fail 'cannot inspect managed Traefik unit overrides'
    [[ -z $dropins ]] || fail 'Traefik unit drop-ins are forbidden by the local issuer guard'
    exec_start=$(systemctl show --property=ExecStart --value "$target_unit") \
        || fail 'cannot inspect the managed Traefik command'
    config_args=$(grep -oE -- '--configFile=[^[:space:];]+' <<< "$exec_start" || true)
    [[ $config_args == --configFile=/etc/keroosha-iac/traefik/static.yml ]] \
        || fail 'managed Traefik command does not use the checked static file'
    env_names=$(systemctl show --property=Environment --value "$target_unit") \
        || fail 'cannot inspect managed Traefik environment'
    if grep -Eiq '(^|[^[:alnum:]_])(TRAEFIK_[[:alnum:]_]*|DNSUPDATE_[[:alnum:]_]*|[[:alnum:]_]*PROXY[[:alnum:]_]*)=' <<< "$env_names"; then
        fail 'managed Traefik unit environment contains an override or proxy'
    fi
    pass_names=$(systemctl show --property=PassEnvironment --value "$target_unit") \
        || fail 'cannot inspect managed Traefik inherited environment'
    if grep -Eiq '(^|[^[:alnum:]_])(TRAEFIK_[[:alnum:]_]*|DNSUPDATE_[[:alnum:]_]*|[[:alnum:]_]*PROXY[[:alnum:]_]*)([[:alnum:]_]|$)' <<< "$pass_names"; then
        fail 'managed Traefik unit inherits an override or proxy'
    fi

    env_files=$(systemctl show --property=EnvironmentFiles --value "$target_unit") \
        || fail 'cannot inspect managed Traefik environment files'
    env_paths=()
    if [[ -n $env_files && $env_files != '-' ]]; then
        mapfile -t env_paths < <(grep -oE '/[^[:space:]]+' <<< "$env_files" || true)
        ((${#env_paths[@]} > 0 && ${#env_paths[@]} <= 1)) \
            || fail 'managed Traefik environment file list is not understood'
    fi
    if [[ $needs_dns == true ]]; then
        ((${#env_paths[@]} == 1)) || fail 'DNS ACME requires the local fixture credentials file'
    else
        ((${#env_paths[@]} == 0)) || fail 'unexpected Traefik environment file without DNS ACME'
    fi
    for env_file in "${env_paths[@]}"; do
        [[ $env_file == /etc/keroosha-iac/traefik/dns-credentials.env \
            && -f $env_file && ! -L $env_file ]] \
            || fail 'managed Traefik uses an unexpected environment file'
        validate_dns_environment_file "$env_file"
    done
fi

printf 'static Traefik issuer configuration accepted\n'

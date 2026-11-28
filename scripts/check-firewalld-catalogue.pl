#!/usr/bin/env perl
# Offline acceptance, inside the disposable Debian 13 guest. Needs libxml-parser-perl.
# Input: a firewalld system-config tree produced by a compiled public Dorothy consumer.
use strict;
use warnings;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use XML::Parser;

@ARGV == 1 or die "usage: $0 GENERATED-SYSTEM-CONFIG\n";
my $tree = abs_path($ARGV[0]) // die "missing catalogue directory\n";
-d $tree && -f "$tree/firewalld.conf" or die "expected a generated system-config tree\n";
$tree !~ m{^/(?:etc|usr|run)(?:/|$)} or die "refusing system directory\n";
system('systemd-detect-virt', '--quiet', '--vm') == 0 or die "requires a disposable virtual machine\n";
my $version = `dpkg-query -W -f='\${Version}' firewalld`;
$? == 0 && $version =~ /^2\.3\.1-/ or die "not the Debian firewalld 2.3.1 catalogue\n";
print "native oracle: firewalld $version\n";
my $core = '/usr/lib/python3/dist-packages/firewall/core';
my (%required, %seen, %excluded);
sub read_text {
    my ($path) = @_;
    open my $file, '<:raw', $path or die "cannot read $path: $!\n";
    local $/; return <$file>;
}
sub source {
    my ($path) = @_;
    my $text = read_text("$core/$path");
    print "native source $path sha256=", sha256_hex($text), "\n";
    $text =~ s/^\s*\#.*$//mg;
    return $text;
}
sub quoted { return $_[0] =~ /"([A-Za-z0-9_,:\-]+)"/g; }
my %dirs = (zone=>'zones',policy=>'policies',service=>'services',ipset=>'ipsets',icmptype=>'icmptypes',helper=>'helpers');
for my $kind (sort keys %dirs) {
    my $text = source("io/$kind.py");
    for my $which (qw(REQUIRED OPTIONAL)) {
        my ($dict) = $text =~ /^    PARSER_${which}_ELEMENT_ATTRS\s*=\s*\{(.*?)^    \}/ms;
        defined $dict or die "missing $kind $which native parser declaration\n";
        while ($dict =~ /\G\s*"([\w-]+)"\s*:\s*(None|\[[^\]]*\])\s*,?/gc) {
            my ($element,$attrs) = ($1,$2);
            $required{"$kind/$element"} = 1;
            $required{"$kind/$element/\@$_"} = 1 for quoted($attrs);
        }
        my $pos = pos($dict) // 0;
        substr($dict,$pos) =~ /^\s*$/ or die "unrecognized native $kind $which grammar\n";
    }
    for my $file (sort glob("$tree/$dirs{$kind}/*.xml")) {
        my $parser = XML::Parser->new(Handlers => {
            Doctype => sub { die "catalogue XML may not contain DOCTYPE\n" },
            Start => sub {
                my ($expat,$element,%attrs) = @_;
                $seen{"$kind/$element"} = 1;
                $seen{"$kind/$element/\@$_"} = 1 for keys %attrs;
                $seen{"ipset-type/$attrs{type}"} = 1 if $element eq 'ipset' && exists $attrs{type};
                $seen{"ipset-option/$attrs{name}"} = 1 if $kind eq 'ipset' && $element eq 'option';
            }});
        $parser->parsefile($file);
    }
}
my $sets = source('ipset.py');
my ($types) = $sets =~ /^IPSET_TYPES\s*=\s*\[(.*?)^\]/ms;
my ($options) = $sets =~ /^IPSET_CREATE_OPTIONS\s*=\s*\{(.*?)^\}/ms;
defined($types) && defined($options) or die "missing native ipset declarations\n";
$required{"ipset-type/$_"} = 1 for quoted($types);
$required{"ipset-option/$_"} = 1 for $options =~ /^\s*"(\w+)"\s*:/mg;
my ($keys) = source('io/firewalld_conf.py') =~ /^valid_keys\s*=\s*\[(.*?)^\]/ms;
defined $keys or die "missing native daemon-key declaration\n";
$required{"daemon/$_"} = 1 for quoted($keys);
my $conf = read_text("$tree/firewalld.conf");
$seen{"daemon/$_"} = 1 for $conf =~ /^\s*([A-Za-z0-9_]+)\s*=/mg;
# Recognized read-only compatibility spellings, explicitly ignored by these native
# object readers. Object names come from filenames; no DSL field can activate them.
$excluded{"$_/$_/\@name"} = 'deprecated object identity; filename is authoritative' for qw(zone service helper icmptype);
$excluded{'zone/zone/@immutable'} = 'deprecated, ignored by the native reader';
$excluded{'zone/masquerade/@enabled'} = 'deprecated boolean spelling; presence of masquerade is the supported form';
$excluded{"$_/source/\@family"} = 'deprecated source family hint; address or rich-rule family determines family' for qw(zone policy);
my @absent = sort grep { !$seen{$_} && !$excluded{$_} } keys %required;
my @unknown = sort grep { !$required{$_} } keys %seen;
print "represented $_\n" for sort grep { $seen{$_} } keys %required;
print "excluded $_: $excluded{$_}\n" for sort grep { $required{$_} && !$seen{$_} } keys %excluded;
die "missing: @absent\nunrecognized output: @unknown\n" if @absent || @unknown;
system('firewall-offline-cmd', "--system-config=$tree", '--check-config') == 0 or die "installed native validator rejected catalogue\n";
printf "native catalogue passed: %d observed features, %d native declarations\n", scalar(keys %seen), scalar(keys %required);

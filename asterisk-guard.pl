#!/usr/bin/perl -w

use strict;
use warnings;

my @whitelist = ('127.0.0.1', '192.168', '100.200.100.200');

open (MYINPUTFILE, "/var/log/asterisk/messages") or die "\n", $!, "Does log file file exist\?\n\n";
my (@failhost);
while (<MYINPUTFILE>) {
    my ($line) = $_;
    chomp($line);
    if ($line =~ m/\' failed for \'(.*?)\' - No matching peer found/) {
        push(@failhost,$1);
    }
    if ($line =~ m/\' failed for \'(.*?)\' - Wrong password/) {
        push(@failhost,$1);
    }
}

if (@failhost) {
    &count_unique(@failhost);
} else {
    #print "no failed registrations.\n";
}

sub whitelisted
{
    my $ip = shift;
    my $wip;
    foreach $wip (@whitelist)
    {
        return 1 if ( $ip =~ /^$wip/ );
    }
    return 0;
}

sub count_unique {
    my @array = @_;
    my %count;
    my $cmd;
    map {
    $_ =~ s/:.*//;
    $count{$_}++;
    } @array;

    #print them out:
    map {
        if ( (!whitelisted($_)) and ($count{$_} > 4) )
        {
            if ( `/sbin/pfctl -t spammers -T show | grep -c $_` == 0 )
            {
                print "Banning $_ because of ${count{$_}} attempts... ";
                $cmd = "/sbin/pfctl -t spammers -T add $_ ; /sbin/pfctl -k $_";
                system($cmd);
                print "Banned!\n";
            }
        }
    } sort keys(%count);
}

#!/usr/bin/perl
# Copyright (c) 2013 Devon H. O'Dell <devon.odell@gmail.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#  - Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
# DAMAGE.

use strict;
use warnings;
use Data::Dumper;
use Getopt::Long;
use Mail::DKIM::Verifier;
use Pod::Usage;

my $keycache;
my $key_file;
my $help = 0;
my $resolution_mode = 0;

my $args = GetOptions (
    'dkim-keyfile|k:s'      => \$key_file,
    'help|h'                => \$help,
    'resolution-mode|r:s'   => \$resolution_mode,
);

pod2usage(-exitstatus => 0, -verbose => 2) if $help;

if ($resolution_mode == 1 && !defined $key_file) {
    print STDERR "Must specify key file if --resolution-mode is set to 1\n";
    exit -1;
}

if (defined $key_file) {
    open FH, "<$key_file" or die "Cannot read $key_file: $!\n";

    $keycache = {};

    while (<FH>) {
        chomp;
	    next if /^\s*$/ || /^\s*#/;
        my ($k, $v) = split /\s+/, $_, 2;
        next if (!$k or !$v);
        $keycache->{$k} = [ bless \$v, "DKV::TXT" ];
    }
}

foreach (@ARGV) {
    my $dkim = Mail::DKIM::Verifier->new();
    my $file = $_;

    open FH, "<$_" or die "Can't open $_: $!\n";
    while (<FH>) {
        # Sanitize for great glory.
        chomp;
        s/\015$//;
        $dkim->PRINT("$_\015\012");
    }

    $dkim->CLOSE;

    my $res = $dkim->result;
    print "$file: $res\n";
}

sub Mail::DKIM::DNS::dkv_query
{
	my ($domain, $type) = @_;
	die "can't lookup $type record" if $type ne "TXT";

    if ($resolution_mode == 1) {
        return @{$keycache->{$domain}} if exists $keycache->{$domain} &&
            ref $keycache->{$domain};
        return Mail::DKIM::DNS::real_query($domain, $type);
    } else {
		my @result = Mail::DKIM::DNS::real_query($domain, $type);

        if (!@result) {
            return @{$keycache->{$domain}} if exists $keycache->{$domain} &&
                ref $keycache->{$domain};
        }

        return;
    }
}

BEGIN {
    *Mail::DKIM::DNS::real_query = *Mail::DKIM::DNS::query;
    *Mail::DKIM::DNS::query = *Mail::DKIM::DNS::dkv_query;
}

package DKV::TXT;

sub type {
	return "TXT";
}

sub char_str_list {
	return ${$_[0]};
}

sub txtdata {
	return ${$_[0]};
}

__END__

=head1 NAME

dkv - DKIM Key Verifier

=head1 SYNOPSIS

dkv [options] [file1, file2, ..., fileN]

    Options:
        --help 		This help message
        --dkimkeys 	The file containing public keys.

=head1 OPTIONS

=over 8

=item B<--help>

Print this manual page and exit.

=item B<--dkim-keyfile>

The file containing keys to use for DKIM validation of supplied email messages.
Defaults to $HOME/.dkimkeys. This file is expected to be formatted in the
following fashion:

selector.address TXT-specification

For example, an old Gmail key could be specified as:

gamma._domainkey.gmail.com k=rsa; t=y; p=MIGfMA0GCSq...

Only one record may be specified on a line. The first whitespace character(s)
encountered serve as the delimiter for the selector address and the key.

=item B<--resolution-mode>

The resolution mode determines the order in which keys will be considered.
The two modes supported are B<0> (DNS first, the default) and B<1> (keyfile
first).  If B<resolution-mode> is set to 1, B<dkim-keyfile> is required.

=back

=head1 DESCRIPTION

B<DKV> is the DKIM Verifier utility. It makes use of the excellent Mail::DKIM
package to validate signatures within a corpus of emails, supplied on the
command line.

B<DKV> is useful for forensic analysis of email corpuses. Key cache files
useful for validating large corpuses can be found at the DKIM Forensics
Project at http://dkfp.9vx.org/.

=head1 AUTHOR

B<DKV> was written by Devon H. O'Dell <devon.odell@gmail.com>.

=head1 TODO

 * Add mbox / maildir support.

 * Add ability to output keys retrieved via DNS to a cache for faster repeated
   searches.

 * Add ability to send messages to DKFP to add keys.

=cut

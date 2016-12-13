#!/usr/bin/perl

##################################################################################################
# This product includes GeoLite2 data created by MaxMind, available from http://www.maxmind.com. #
##################################################################################################

use Data::Dumper;
use POSIX qw(strftime);
use Text::CSV_XS;
use MaxMind::DB::Reader;
use strict;

sub add_alert {
	my $data = shift;
	my $alert_file = "/tmp/ezproxy_audit_result";
	open my $alert_fh, '>>', $alert_file or die "Can't open $alert_file: $!";
	print $alert_fh join("\t",@{$data}),"\n";
	close $alert_fh;
}

sub mmdb_query {
	my $ip = shift;
	my $mmdb_file = "/path/to/GeoLite2-Country.mmdb";
	my $reader = MaxMind::DB::Reader->new( file => $mmdb_file );
	my $record = $reader->record_for_address($ip);
	return $record ? $record : 0;
}

# Set file path
my $blacklist = "/path/to/blacklist.csv";
my $audit_file = "/path/to/ezproxy/audit/".(strftime "%Y%m%d", localtime).".txt";
open my $audit_fh, '<:encoding(UTF-8)', $audit_file or die "Can't open $audit_file: $!";

DATA: while ( <$audit_fh> ) {
	chomp $_;
	if ($_ =~ /Login.Success/) {
		my @data = split /\t/, $_;
		while (@data) {
        	my ($timestamp, $action, $ip, $username, $cookie) = splice(@data, 0, 5);
			
			# Ignore Private IP range
			next DATA if $ip =~ /^(192\.168|10\.)/;
			
			# Cookie exists in blacklist
			my $csv = Text::CSV_XS->new ({ binary => 1, auto_diag => 1, eol => $/ });
			my @rows;
			open my $blacklist_fh, '<', $blacklist;
			if ($blacklist_fh) {
				# Read/parse CSV
				while (my $row = $csv->getline($blacklist_fh)) {
					# $row indeces 0, 1 and 2 map to ip, country, and cookie, respectively.
					next DATA if ($cookie eq $row->[2]);	
				}
				$csv->eof or $csv->error_diag();
				close $blacklist_fh;
			}

			# MaxMind DB Query
			my $result = mmdb_query($ip);
			
			# Add to blacklist if access outside of USA
			if ($result->{registered_country}->{iso_code} !~ /^US$/) {
				open my $blacklist_fh, '>>', $blacklist or die "Can't open $blacklist: $!";
				$csv->print($blacklist_fh, [$ip,$result->{registered_country}->{names}->{en},$cookie]);
				close $blacklist_fh;
				add_alert([$timestamp, $action, $ip, $username, $cookie, "Access from $result->{registered_country}->{names}->{en}!"]);
			}

		}
	}
}
exit 0;
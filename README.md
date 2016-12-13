# ezproxy-geolocation-audit
written by Justin Beerley

## Introduction
The purpose of this script is to parse EZProxy audit log files, query the geolocation for successful logins, and report the findings.

## Requirements
Perl, MaxMind::DB::Reader or MaxMind::DB::Reader::XS, Text::CSV or Text::CSV_XS

>_We recommend installing the libmaxminddb C library. https://github.com/maxmind/_

EZProxy should be configured with the __Audit Most__ directive.

GeoLite2 Country MaxMind DB. http://www.maxmind.com.

## Configuration
You'll need to set several path and filenames for the Perl script to run successfully.

	15: my $alert_file = "/path/to/audit_results.txt";

	23: my $mmdb_file = "/path/to/GeoLite2-Country.mmdb";

	30: my $blacklist = "/path/to/blacklist.csv";

	31: my $audit_file = "/path/to/ezproxy/audit/".(strftime "%Y%m%d", localtime).".txt";
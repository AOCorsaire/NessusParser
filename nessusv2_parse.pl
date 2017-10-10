#!/usr/bin/perl

#
# Parse version 2 nessus files
#
# perl nessusv2_parser.pl <nessus file>
#
# A A Dickinson A&O Corsaire
# 
# History
#
# 16/05/16      Print and sort by severity
# 29/02/16      Initial Version
#
use strict;
use warnings;
use Data::Dumper;
use lib qw(/opt/local/lib);
use Corsaire::Parser;

my $file = $ARGV[0];

my $results = Corsaire::Parser::parser_nessusv2($file);

open(my $fh, ">", "./internal_nessus_output.txt");
foreach my $d (sort { $b->{severity} <=> $a->{severity} } @$results) {
        print "$d->{ip}\t$d->{pluginID}\t$d->{severity}\t$d->{pluginName}\n";
        print $fh Dumper $d;
}
close($fh);


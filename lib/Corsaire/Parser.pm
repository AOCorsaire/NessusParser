package Corsaire::Parser;

use strict;
use warnings;
use XML::Twig;

sub parser_nessusv2 {

	my ($file) = @_;

	my $p = {};


	my @atts = ("port", "svc name", "protocol", "severity", "pluginID", "pluginName", "pluginFamily");
	my @elems = ("risk_factor", "synopsis", "description", "solution", "plugin_output", "see_also", "cve", "bid", "xref", "plugin_modification_date", "plugin_publication_date", "patch_publication_date", "vuln_publication_date", "exploitability_ease", "exploit_available", "exploit_framework_canvas", "exploit_framework_metasploit", "exploit_framework_core", "metasploit_name", "canvas_package", "cvss_vector", "cvss_base_score", "cvss_temporal_score", "plugin_type", "plugin_version", "cm:compliance-info", "cm:compliance-result", "cm:compliance-actual-value", "cm:compliance-check-id", "cm:compliance-audit-file", "cm:compliance-check-name");
	
	my @results;

	my $xs = XML::Twig->new(
		twig_roots => {
			'ReportHost' => sub {
				my ($t, $host) = @_;
				my $ip = $host->{'att'}{'name'};
				my @keys = $host->children();
				foreach my $k (@keys) {
					my $d = {
						ip => $ip,
					};
					foreach (@atts) {
						my $tmp = $k->{'att'}{"$_"};
						next if not defined $tmp;
						$d->{$_} = $tmp;
					}
					foreach (@elems) {
						my $el = $k->first_child($_);
						next if not defined $el;
						$d->{$_} = $el->text;
					}
					next unless exists $d->{pluginID}; 
					push @results, $d;
				}
			},
		},
	);
	
	$xs->parsefile($file);

	return \@results;

}

1;

# NessusParser
Parse Nessus Files

# Requirements
Perl

XML::Twig

# Examples
```
ant@host:~/$ perl nessusv2_parse.pl 192network.nessus 
192.168.0.1	78555	4	OpenSSL Unsupported
192.168.0.1	93814	4	OpenSSL 1.0.1 < 1.0.1u Multiple Vulnerabilities (SWEET32)
192.168.0.3	84729	4	Microsoft Windows Server 2003 Unsupported Installation Detection
192.168.0.3	11057	3	TCP/IP Initial Sequence Number (ISN) Reuse Weakness
192.168.0.9	11057	3	TCP/IP Initial Sequence Number (ISN) Reuse Weakness
192.168.0.9	89081	3	OpenSSL 1.0.1 < 1.0.1s Multiple Vulnerabilities (DROWN)
192.168.0.9	96451	3	Apache 2.4.x < 2.4.25 Multiple Vulnerabilities (httpoxy)
192.168.0.10	26928	2	SSL Weak Cipher Suites Supported
... [snip] ...
```

Also drops an internal file that contains a Dumper of the data structure for further analysis

```
ant@host:~/git$ head -n 20 internal_nessus_output.txt 
$VAR1 = {
          'ip' => '192.168.0.1',
          'pluginFamily' => 'Web Servers',
          'cvss_base_score' => '10.0',
          'synopsis' => 'An unsupported service is running on the remote host.',
          'plugin_modification_date' => '2017/01/12',
          'plugin_type' => 'remote',
          'risk_factor' => 'Critical',
          'cvss_vector' => 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C',
          'plugin_publication_date' => '2014/10/17',
          'port' => '8081',
          'see_also' => 'https://www.openssl.org/policies/releasestrat.html
http://www.nessus.org/u?4d55548d',
          'solution' => 'Upgrade to a version of OpenSSL that is currently supported.',
          'pluginID' => '78555',
          'protocol' => 'tcp',
          'description' => 'According to its banner, the remote web server is running a version of OpenSSL that is no longer supported.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.',
          'plugin_output' => '
... [snip] ...
```

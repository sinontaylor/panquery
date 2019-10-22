# Description

panquery (v1.0) - Query tool for firewall databases created with panmanager

Panquery is a CLI tool for Palo Alto database files create with panmanager. Panquery can list objects, find implicit/explicit policy matches, print expanded rules (eg groups + members) and show unused objects.

The following output is from the script help:

Usage:

	sudo panquery.pl --db <firewall database name> <options>

Options:

	--list {types|type|all} 			      : lists available object types, all object names of 'type x' or all objects
	--obj <name> [{--ipvf|--regex}]			: lists object contents exactly matching <name>
							                        : --ipvf outputs ip/cidr format for address/address-group objects
							                        : --regexp outputs object names matching pattern
	--grp <name> [--match]				      : lists parent groups for object matching <name>
			 				                        : --match will find all nested groups that object indirectly appears in (e.g. not just parent groups)
	--ip <ip> [--match]				          : lists IP and explicit matching objects. Also lists any address groups/tags the matched object is a member of
							                        : --match will find implicit match in address groups and print containing cidr (e.g. within netmask)
	--rule {object name|ip} [--match]		: lists rules with expanded fields for given object or explicit IP (will find objects hidden in groups)
							                        : --match if IP provided will find implicit match, e.g. if IP would match /24 object in rule
	--debug						                  : debug printing information
	--dump [{--policy|--nats}]			    : prints the database, expanded tags and rules
							                        : --policy prints expanded rules only
							                        : --nats prints expanded nats only

Examples:

	sudo panquery.pl --db panmanager-output-file.csv --list types
	sudo panquery.pl --db panmanager-output-file.csv --list addr
	sudo panquery.pl --db panmanager-output-file.csv --list all
	sudo panquery.pl --db panmanager-output-file.csv --obj <address>
	sudo panquery.pl --db panmanager-output-file.csv --obj <address group>
	sudo panquery.pl --db panmanager-output-file.csv --obj <address group> --ipvf
	sudo panquery.pl --db panmanager-output-file.csv --obj <application group>
	sudo panquery.pl --db panmanager-output-file.csv --obj <service group>
	sudo panquery.pl --db panmanager-output-file.csv --obj <address group>
	sudo panquery.pl --db panmanager-output-file.csv --obj <tag>
	sudo panquery.pl --db panmanager-output-file.csv --obj <pattern> --regex
	sudo panquery.pl --db panmanager-output-file.csv --grp <address>
	sudo panquery.pl --db panmanager-output-file.csv --grp <address> --match
	sudo panquery.pl --db panmanager-output-file.csv --grp <application>
	sudo panquery.pl --db panmanager-output-file.csv --grp <service>
	sudo panquery.pl --db panmanager-output-file.csv --ip 8.8.8.8
	sudo panquery.pl --db panmanager-output-file.csv --ip 8.8.8.8 --match
	sudo panquery.pl --db panmanager-output-file.csv --rule <address>
	sudo panquery.pl --db panmanager-output-file.csv --rule <application>
	sudo panquery.pl --db panmanager-output-file.csv --rule <service>
	sudo panquery.pl --db panmanager-output-file.csv --rule <tag>
	sudo panquery.pl --db panmanager-output-file.csv --rule <tag> --debug
	sudo panquery.pl --db panmanager-output-file.csv --rule 8.8.8.8
	sudo panquery.pl --db panmanager-output-file.csv --rule 8.8.8.8 --match
	sudo panquery.pl --db panmanager-output-file.csv --dump
	sudo panquery.pl --db panmanager-output-file.csv --dump --policy
	sudo panquery.pl --db panmanager-output-file.csv --dump --nats

# Dependencies

File::Basename;
FileHandle;
Getopt::Long;
Tie::IxHash;
Data::Validate::IP qw(is_ipv4 is_ipv6);
Net::IP::Match::Regexp qw(create_iprange_regexp_depthfirst match_ip);
Text::CSV_XS;

# Caveats

Does not suport IPv6 objects.

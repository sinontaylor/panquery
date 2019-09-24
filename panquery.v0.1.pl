#!/usr/bin/perl
#
my $version = "2.4";
# Date          04 July, 2017
# Purpose       Palo Alto Firewall Management Query Tool to report on rule and object usage using offline configs
# Revision      24 September, 2019
#
# 0.4 - Added --grp option to query any type of group
# 0.5 - switched name of script and updated printing for --grp option
# 0.6 - edited group output for all
# 0.7 - added ability to query Global Objects and added GO into own hashes
# 0.8 - added dump option
# 0.9 - added -obj option to find groups  address is member of
# 1.0 - added Check Point GO support
# 1.1 - output dump as CP csv format and expand on cli options
# 1.2 - edited to permit pattern match for --obj option
# 1.3 - added ability to find an IP that is contained/matched by rule(s), excludes matches for "any". Also updated --ip and --grp flags output
# 1.4 - added ability to open Check Point CMA objects - nat/sec files are named after firewalls not cmas - see readCPRules(). Also exclude group support.
# 1.5 - added ability to return all nested groups of an object
# 1.6 - captured tags on address objects and added these to tag members field
# 1.7 - bug fix in obj print output
# 1.8 - run query against firewall db not dg db
# 1.9 - dump out all rules
# 2.0 - include post rules and support for standalone firewalls
# 2.1 - added --depth option to allow printing of immediate group memberd only
# 2.2 - updated typos on comment/s and net/mask variables preventing their output
# 2.3 - re-wrote PA parser to use new format
# 2.4 - fixed up for unused objects

#use strict;
#use warnings;
use Data::Dumper;
use File::Basename;
use FileHandle;
use Getopt::Long;
use Tie::IxHash; # for ordered hash for rules section as no rule uid exists in Palo Alto
use Data::Validate::IP qw(is_ipv4);
use Net::IP::Match::Regexp qw(create_iprange_regexp_depthfirst match_ip);
use Net::Netmask;
use NetAddr::IP;
use Net::IPv4Addr qw (:all);
use Data::Validate::IP qw(is_ipv4);
use Text::CSV_XS;

my $me = basename($0, ".pl");
my $rule;
my $database;
my $grp;
my $ip;
my @lists;
my $itsec;
my $ipvf;
my $regex;
my $match;
my $policy;
my $obj;
my $debug;
my $depth;
my $global;
my $dump;
my $unused;
my $duplicates;
my $help;
my $baseDir = "/root/Documents";
my $scriptDir = $baseDir."/Scripts";
my $outputDir = $baseDir."/OUTPUT";
my $staticDir = $baseDir."/static_data";
my $inputDir = $scriptDir."/unused-rules";
my $dgDir = $staticDir."/dg-objects";
my $paDir = $staticDir."/pa-objects";
my $cmaDir = $staticDir."/cma-objects";

my $fh = new FileHandle;
my $goFile = "PA-objects.csv";
my $objFile = "";
my $dgfp = "eag-mgt-panorama1-dg_";
my $dgofs = "gp__objects.csv";
my $dgrfs = "gp__pre-rules.csv";
my $dgprfs = "gp__post-rules.csv";
my $cmaofs = "objects.csv";
my @networks;
my @parentGroups;
my @parentRules;
my %addresses = ();
my %address_groups = ();
my %application_groups = ();
my %services = ();
my %service_groups = ();
my %tags = ();
my %exclGroups = ();
my %Gaddresses = ();
my %Gaddress_groups = ();
my %Gapplication_groups = ();
my %Gservices = ();
my %Gservice_groups = ();
my %Gtags = ();
my %rules = ();
tie %rules, 'Tie::IxHash';
my %capabilities = ();
my %appids = ();
my %appNames = ();
my %dgs = ();
my %fws = ();
my %used_addresses = ();
my %used_applications = ();
my %used_services = ();
my %used_tags = ();
my %applications = ();
my %application_filters = ();

my %netmasks = ();
$netmasks{"255.255.255.255"} = "32";
$netmasks{"255.255.255.254"} = "31";
$netmasks{"255.255.255.252"} = "30";
$netmasks{"255.255.255.248"} = "29";
$netmasks{"255.255.255.240"} = "28";
$netmasks{"255.255.255.224"} = "27";
$netmasks{"255.255.255.192"} = "26";
$netmasks{"255.255.255.128"} = "25";
$netmasks{"255.255.255.0"} = "24";
$netmasks{"255.255.254.0"} = "23";
$netmasks{"255.255.252.0"} = "22";
$netmasks{"255.255.248.0"} = "21";
$netmasks{"255.255.240.0"} = "20";
$netmasks{"255.255.224.0"} = "19";
$netmasks{"255.255.192.0"} = "18";
$netmasks{"255.255.128.0"} = "17";
$netmasks{"255.255.0.0"} = "16";
$netmasks{"255.254.0.0"} = "15";
$netmasks{"255.252.0.0"} = "14";
$netmasks{"255.248.0.0"} = "13";
$netmasks{"255.240.0.0"} = "12";
$netmasks{"255.224.0.0"} = "11";
$netmasks{"255.192.0.0"} = "10";
$netmasks{"255.128.0.0"} = "9";
$netmasks{"255.0.0.0"} = "8";
$netmasks{"254.0.0.0"} = "7";
$netmasks{"252.0.0.0"} = "6";
$netmasks{"248.0.0.0"} = "5";
$netmasks{"240.0.0.0"} = "4";
$netmasks{"224.0.0.0"} = "3";
$netmasks{"192.0.0.0"} = "2";
$netmasks{"128.0.0.0"} = "1";
$netmasks{"0.0.0.0"} = "0";

my %netbits = ();
$netbits{"32"} = "255.255.255.255";
$netbits{"31"} = "255.255.255.254";
$netbits{"30"} = "255.255.255.252";
$netbits{"29"} = "255.255.255.248";
$netbits{"28"} = "255.255.255.240";
$netbits{"27"} = "255.255.255.224";
$netbits{"26"} = "255.255.255.192";
$netbits{"25"} = "255.255.255.128";
$netbits{"24"} = "255.255.255.0";
$netbits{"23"} = "255.255.254.0";
$netbits{"22"} = "255.255.252.0";
$netbits{"21"} = "255.255.248.0";
$netbits{"20"} = "255.255.240.0";
$netbits{"19"} = "255.255.224.0";
$netbits{"18"} = "255.255.192.0";
$netbits{"17"} = "255.255.128.0";
$netbits{"16"} = "255.255.0.0";
$netbits{"15"} = "255.254.0.0";
$netbits{"14"} = "255.252.0.0";
$netbits{"13"} = "255.248.0.0";
$netbits{"12"} = "255.240.0.0";
$netbits{"11"} = "255.224.0.0";
$netbits{"10"} = "255.192.0.0";
$netbits{"9"} = "255.128.0.0";
$netbits{"8"} = "255.0.0.0";
$netbits{"7"} = "254.0.0.0";
$netbits{"6"} = "252.0.0.0";
$netbits{"5"} = "248.0.0.0";
$netbits{"4"} = "240.0.0.0";
$netbits{"3"} = "224.0.0.0";
$netbits{"2"} = "192.0.0.0";
$netbits{"1"} = "128.0.0.0";
$netbits{"0"} = "0.0.0.0";

########################################################################################
#
# Check inputs, getopt "=" mandatory, ":" optional
#
########################################################################################

GetOptions(
        "db=s" => \$database,
        "list:s" => \@lists,
        "grp:s" => \$grp,
        "obj:s" => \$obj,
        "ip:s" => \$ip,
        "rule:s" => \$rule,
        "depth:s" => \$depth,
        "itsec" => \$itsec,
        "ipvf" => \$ipvf,
        "regex" => \$regex,
        "policy" => \$policy,
        "global" => \$global,
        "match" => \$match,
        "debug" => \$debug,
        "dump:s" => \$dump,
        "unused" => \$unused,
        "duplicates" => \$duplicstes,
        "help" => \$help
);

usage($version) and exit if ($help);
usage($version) and print "ERROR01 : db must not be empty\n" and exit if (!$database);
usage($version) and print "ERROR02 : one of list, obj, grp, ip, rule, unused or dump required\n" and exit if ((!@lists) and (!$obj) and (!$grp) and (!$ip) and (!$rule) and (!$unused) and (!$dump));

########################################################################################
#
# Read in various object types from the offline object file
#
########################################################################################

# read Panorama shared
#readPAObjects(\%Gapplication_groups, \%Gaddress_groups, \%Gaddresses, \%Gservices, \%Gservice_groups, \%Gtags, $goFile, $inputDir);
#readPaloAPIFormat(\%Gapplication_groups, \%Gaddress_groups, \%Gaddresses, \%Gservices, \%Gservice_groups, \%Gtags, $goFile, $inputDir);

# read this file
# readPAObjects(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $database, $inputDir);
readPaloAPIFormat(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $database, $inputDir);

#readPAObjects(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $vsysobjFile, $inputDir);
#readPAObjects(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $sharedobjFile, $inputDir);

#readAppIDs(\%appids, \%appNames);

########################################################################################
#
# cli switches : --unused
#
########################################################################################

if ($unused){

	#######################################################################################
	#
	# Find out which objects are used in the policy provided
	#
	#######################################################################################

	my $csv	 = Text::CSV_XS->new ({ binary => 1, auto_diag => 1 });
	open my $fh, "<:encoding(utf8)", $database or die "Cannot open $database: $!";

	$csv->column_names ($csv->getline ($fh));
	my $location;

	while (my $href = $csv->getline_hr ($fh)) {

		next if ($href->{objtype} !~ /rule/);
		$location = $href->{location};

       	 	my $src = $href->{source};
        	$src =~ s/[\[\]'\s]+//g;

        	my $dst = $href->{destination};
        	$dst =~ s/[\[\]'\s]+//g;

        	my $app = $href->{application};
        	$app =~ s/[\[\]'\s]+//g;

        	my $svc = $href->{service};
        	$svc =~ s/[\[\]'\s]+//g;

        	my $tag = $href->{tag};
        	$tag =~ s/[\[\]'\s]+//g;

        	if (($src) and ($src ne "any")){
                	if ($src =~ /\,/){
                        	my @data = split (/\,/, $src);
                        	foreach my $item (@data){
                                	$used_addresses{$item} = $item;
                        	}
                	} else {
                        	$used_addresses{$src} = $src;
                	}
        	}

        	if (($dst) and ($dst ne "any")){
                	if ($dst =~ /\,/){
                        	my @data = split (/\,/, $dst);
                        	foreach my $item (@data){
                        	$used_addresses{$item} = $item;
                        	}
                	} else {
                        	$used_addresses{$dst} = $dst;
                	}
        	}

        	if (($app) and ($app ne "any")){
                	if ($app =~ /\,/){
                        	my @data = split (/\,/, $app);
                        	foreach my $item (@data){
                                	$used_applications{$item} = $item;
                        	}
                	} else {
                        	$used_applications{$app} = $app;
                	}
        	}

        	if (($svc) and ($svc ne "application-default") and ($svc ne "any")) {
                	if ($svc =~ /\,/){
                        	my @data = split (/\,/, $svc);
                        	foreach my $item (@data){
                                	$used_services{$item} = $item;
                        	}
                	} else {
                        	$used_services{$svc} = $svc;
                	}
        	}

        	if (($tag) and ($tag ne "any")){
                	if ($tag =~ /\,/){
                        	my @data = split (/\,/, $tag);
                        	foreach my $item (@data){
                                	$used_tags{$item} = $item;
                       	 	}
                	} else {
                        	$used_tags{$tag} = $tag;
                	}
        	}

	}
	$fh->close();

	#######################################################################################
	#
	# For each rule object if its a group then all members assumed 'seen' so add them into 'used' hashes
	#
	#######################################################################################

	# figure out the members used in static address groups
	foreach my $object (sort keys %used_addresses){
        	if (exists($address_groups{$object})){
                	if (exists($address_groups{$object}{'members'})){
                        	foreach my $member (@{$address_groups{$object}{'members'}}){
                                	$used_addresses{$member} = $member;
                        	}
                	}
        	}
	}

	# figure out the tags used in dynamic address groups
	foreach my $object (sort keys %used_addresses){
        	if (exists($address_groups{$object})){
                	if (exists($address_groups{$object}{'tags'})){
                        	foreach my $tag (@{$address_groups{$object}{'tags'}}){
                                	$used_tags{$tag} = $tag;
                        	}
               	 	}
        	}
	}

	# figure out the services used in service groups
	foreach my $object (sort keys %used_services){
        	if (exists($service_groups{$object})){
                	if (exists($service_groups{$object}{'members'})){
                        	foreach my $member (@{$service_groups{$object}{'members'}}){
                                	$used_services{$member} = $member;
                        	}
                	}
        	}
	}

	# figure out the applications used in application groups
	foreach my $object (sort keys %used_applications){
        	if (exists($application_groups{$object})){
                	if (exists($application_groups{$object}{'members'})){
                        	foreach my $member (@{$application_groups{$object}{'members'}}){
                                	$used_applications{$member} = $member;
                        	}
                	}
        	}
	}

	#######################################################################################
	#
	# Figure out unused objects
	#
	#######################################################################################

	# address and address groups cannot share same name
	my %all_addresses = (%address_groups, %addresses);
	foreach my $object (sort keys %all_addresses){
        	if (!exists($used_addresses{$object})){
                	print "addresses object unused \'$object\'\n";
			if (exists($addresses{$object})){
				print "palo,address,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
			} elsif (exists($address_groups{$object})){
				print "palo,address-group,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
			} else {
                		print "ERROR addresses object missing from $database \'$object\'\n";
			}
        	} else {
                	print "addresses object used \'$object\'\n";
        	}
	}

	# applications, application groups and application filters cannot share same name
	my %all_applications = (%applications, %application_groups, %application_filters);
	foreach my $object (sort keys %all_applications){
        	if (!exists($used_applications{$object})){
                	print "applications object unused \'$object\'\n";
			if (exists($applications{$object})){
				print "palo,application,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
			} elsif (exists($application_groups{$object})){
				print "palo,application-group,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
			} elsif (exists($application_filters{$object})){
				print "palo,application-filter,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
			}
        	} else {
                	print "applications object used \'$object\'\n";
		}
	}

	my $found = "TRUE";
	# service and service groups CAN share same name
	foreach my $object (sort keys %services){
		if (!exists($used_services{$object})){
			undef $found;
                } else {
                        print "services object used \'$object\'\n";
		}
	}

        foreach my $object (sort keys %service_groups){
        	if (!exists($used_services{$object})){
			if (!$found){
                        	print "services object unused \'$object\'\n";
				if (exists($services{$object})){
					print "palo,service,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
				}
				if (exists($service_groups{$object})){
					print "palo,service-group,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
				}
			}
                } else {
                        print "services object used \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %tags){
        	if (!exists($used_tags{$object})){
                	print "tag object unused \'$object\'\n";
			print "palo,tag,delete,".$location.",\"".$object."\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n";
        	} else {
                	print "tag object used \'$object\'\n";
		}
	}

	#######################################################################################
	#
	# Check for items in the policy that are not in the object file
	#
	#######################################################################################

	foreach my $object (sort keys %used_addresses){
        	if (!exists($all_addresses{$object})){
                	print "ERROR addresses object missing from $database \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %used_applications){
        	if (!exists($all_applications{$object})){
               	 	print "ERROR applications object missing from $database \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %used_services){
        	if ((!exists($services{$object})) and (!exists($service_groups{$object}))){
                	print "ERROR services object missing from $database \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %used_tags){
        	if (!exists($tags{$object})){
                	print "ERROR tag object missing from $database \'$object\'\n";
        	}
	}
	exit;
}

########################################################################################
#
# cli switches : --duplicates
#
########################################################################################

########################################################################################
#
# cli switches : --list
#
########################################################################################

foreach my $list (@lists){
        if ($list eq "types"){
                print "addr,port,addrgrp,appgrp,svcgrp,exclgrp,tag,all\n";
        } elsif ($list eq "tag"){
                printObjType(\%tags);
        } elsif ($list eq "addr"){
                printObjType(\%addresses);
        } elsif ($list eq "port"){
                printObjType(\%services);
        } elsif ($list eq "addrgrp"){
                printObjType(\%address_groups);
        } elsif ($list eq "appgrp"){
                printObjType(\%application_groups);
        } elsif ($list eq "svcgrp"){
                printObjType(\%service_groups);
        } elsif ($list eq "exclgrp"){
                printObjType(\%exclGroups);
        } elsif ($list eq "all"){
                printObjType(\%addresses);
                printObjType(\%address_groups);
                printObjType(\%services);
                printObjType(\%service_groups);
                printObjType(\%application_groups);
                printObjType(\%exclGroups);
                printObjType(\%tags);
        }
}

if (@lists){
        exit;
}

########################################################################################
#
# cli switches : --obj --ipvf
#
########################################################################################

if ($obj){

        if (exists($tags{$obj})){
                print "$obj,$tags{$obj}{'comment'},";
                printMembers(\@{$tags{$obj}{'members'}});
                print "\n";
        }

        if (exists($addresses{$obj})){
                if (defined $ipvf){
                        print "$addresses{$obj}{'cidr'}\n";
                } else {
                        print "$obj,$addresses{$obj}{'cidr'},$addresses{$obj}{'ip'},$addresses{$obj}{'netmask'},$addresses{$obj}{'colour'},$addresses{$obj}{'comment'},$addresses{$obj}{'tag'}\n";
                }
        }

        if (exists($services{$obj})){
                print "$obj,$services{$obj}{'protocol'},$services{$obj}{'port'},$services{$obj}{'colour'},$services{$obj}{'comment'}\n";
        }

        if (exists($address_groups{$obj})){
                if (defined $ipvf){
                        printMembersExpanded(\@{$address_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                } elsif (defined $depth){
                        printMembers(\@{$address_groups{$obj}{'members'}});
                } else {
                        print "$obj,";
                        printMembersExpanded(\@{$address_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                        print "\n";
                }
        }

        if (exists($Gaddress_groups{$obj})){
                if (defined $ipvf){
                        printMembersExpanded(\@{$Gaddress_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                } elsif (defined $depth){
                        printMembers(\@{$Gaddress_groups{$obj}{'members'}});
                } else {
                        print "$obj,";
                        printMembersExpanded(\@{$Gaddress_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                        print "\n";
                }
        }

        if (exists($service_groups{$obj})){
                print "$obj,";
                printMembers(\@{$service_groups{$obj}{'members'}});
                print "\n";
        }

        if (exists($application_groups{$obj})){
                print "$obj,";
                printMembers(\@{$application_groups{$obj}{'members'}});
                print "\n";
        }

        if (exists($exclGroups{$obj})){
                if (defined $ipvf){
                        foreach my $network (@{$exclGroups{$obj}{'delta'}}){
                                print "$network\n";
                        }
                } else {
                        print "$obj,";
                        print "$exclGroups{$obj}{'incl'}";
                        print ",";
                        print "$exclGroups{$obj}{'excl'}";
                        print "\n";
                }
        }

        if ($regex){
                foreach (keys %tags){
                        if ($_ =~ m/$obj/){
                                print "tag,$_\n";
                        }
                }
                foreach (keys %Gtags){
                        if ($_ =~ m/$obj/){
                                print "Gtag,$_\n";
                        }
                }
                foreach (keys %addresses){
                        if ($_ =~ m/$obj/){
                                print "addr,$_\n";
                        }
                }
                foreach (keys %Gaddresses){
                        if ($_ =~ m/$obj/){
                                print "Gaddr,$_\n";
                        }
                }
                foreach (keys %services){
                        if ($_ =~ m/$obj/){
                                print "port,$_\n";
                        }
                }
                foreach (keys %Gservices){
                        if ($_ =~ m/$obj/){
                                print "Gport,$_\n";
                        }
                }
                foreach (keys %address_groups){
                        if ($_ =~ m/$obj/){
                                print "addrgrp,$_\n";
                        }
                }
                foreach (keys %Gaddress_groups){
                        if ($_ =~ m/$obj/){
                                print "Gaddrgrp,$_\n";
                        }
                }
                foreach (keys %service_groups){
                        if ($_ =~ m/$obj/){
                                print "svcgrp,$_\n";
                        }
                }
                foreach (keys %Gservice_groups){
                        if ($_ =~ m/$obj/){
                                print "Gsvcgrp,$_\n";
                        }
                }
                foreach (keys %application_groups){
                        if ($_ =~ m/$obj/){
                                print "appgrp,$_\n";
                        }
                }
                foreach (keys %Gapplication_groups){
                        if ($_ =~ m/$obj/){
                                print "Gappgrp,$_\n";
                        }
                }
                foreach (keys %exclGroups){
                        if ($_ =~ m/$obj/){
                                print "exclgrp,$_\n";
                        }
                }
        }
        exit;
}

########################################################################################
#
# cli switches : --grp
#
########################################################################################

if ($grp){
        if ((exists($addresses{$grp})) or (exists($address_groups{$grp})) or (exists($Gaddresses{$grp}))){
                printGroups(\%address_groups, $grp, $match);
        } elsif ((exists($application_groups{$grp})) or (exists($appids{$grp})) or (exists($appNames{$grp}))){
                printGroups(\%application_groups, $grp, $match);
        } elsif ((exists($service_groups{$grp})) or (exists($services{$grp})) or (exists($Gservices{$grp}))){
                printGroups(\%service_groups, $grp, $match);
        } else {
                print "ERROR04: object $grp not found!\n";
        }
        exit;
}

########################################################################################
#
# cli switches : --ip
#
########################################################################################

if ($ip){
        if (is_ipv4($ip)) {
                my @matchedObjects;
                findObjectFromIP(\%addresses, \@matchedObjects, $ip);
                foreach my $objName (@matchedObjects){
                        print "$ip,$objName\n";
                        printGroups(\%address_groups, $objName, $match);
                }

                if ($match){
                        my @matchedEG;
                        # add support for exclGroups
                        foreach my $exclGroup (sort keys %exclGroups){
                                if (exists($exclGroups{$exclGroup}{'objre'})){
                                        if (match_ip($ip, $exclGroups{$exclGroup}{'objre'})){
                                                push @matchedEG, $exclGroup;
                                        }
                                }
                        }
                        if (@matchedEG){
                                printMembers(\@matchedEG);
                                print "\n";
                        }

                }

                # check tags
                my @matchedTags;
                foreach my $tag (sort keys %tags){
                        foreach my $member (@{$tags{$tag}{'members'}}) {
                                if ($member eq $ip){
                                        push @matchedTags, $tag;
                                }
                        }
                }
                if (@matchedTags){
                        print "$ip,";
                        printMembers(\@matchedTags);
                        print "\n";
                }
        } else {
                print "ERROR05 : IP $ip is invalid\n";
        }
        exit;
}

########################################################################################
#
# Read in the rules from the offline rules file
#
########################################################################################

if ($database =~ /cma/){
        readCPRules($database, $cmaDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses, \%exclGroups);
} elsif ($database =~ /vsys/){

        if ($global){
                # find my parent device group
                my $dg = $fws{$database};
                $dg =~ s/_gp//g;
                $objFile = join("_", ("$dgfp", "$dg", "$dgrfs"));
                $rules{'***START DEVICE GROUP PRE RULES***'}{'name'} = "***START DEVICE GROUP PRE RULES***";
                #readPARules($objFile, $dgDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses);
                $rules{'***END DEVICE GROUP PRE RULES***'}{'name'} = "***END DEVICE GROUP PRE RULES***";
                $rules{'***START LOCAL FIREWALL RULES***'}{'name'} = "***START LOCAL FIREWALL RULES***";
        }

        $objFile = join("-", ("$database", "rules.csv"));
        #readPARules($objFile, $paDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses);

        if ($global){
                # find my parent device group
                my $dg = $fws{$database};
                $dg =~ s/_gp//g;
                $rules{'***END LOCAL FIREWALL RULES***'}{'name'} = "***END LOCAL FIREWALL RULES***";
                $rules{'***START DEVICE GROUP POST RULES***'}{'name'} = "***START DEVICE GROUP POST RULES***";
                $objFile = join("_", ("$dgfp", "$dg", "$dgprfs"));
                #readPARules($objFile, $dgDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses);
                $rules{'***END DEVICE GROUP POST RULES***'}{'name'} = "***END DEVICE GROUP POST RULES***";
        }

} elsif ($database !~ /global/){

        # eg we are just device group here

        $objFile = join("_", ("$dgfp", "$database", "$dgrfs"));
        $rules{'***START DEVICE GROUP PRE RULES***'}{'name'} = "***START DEVICE GROUP PRE RULES***";
        #readPARules($objFile, $dgDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses);
        $rules{'***END DEVICE GROUP PRE RULES***'}{'name'} = "***END DEVICE GROUP PRE RULES***";
        $rules{'***START DEVICE GROUP POST RULES***'}{'name'} = "***START DEVICE GROUP POST RULES***";
        $objFile = join("_", ("$dgfp", "$database", "$dgprfs"));
        #readPARules($objFile, $dgDir, \%rules, \%address_groups, \%addresses, \%tags, \%Gaddress_groups, \%Gaddresses);
        $rules{'***END DEVICE GROUP POST RULES***'}{'name'} = "***END DEVICE GROUP POST RULES***";
}

########################################################################################
#
# cli switches : --dump --debug --policy
#
########################################################################################

if (($dump) and ($policy)){
        foreach my $rule (keys %rules) {
                push (@parentRules, $rule);
        }
        if ($database =~ /cma/){
                printCPRules(\%address_groups, \%addresses, \%services, \%service_groups, \%exclGroups, \%rules, \@parentRules);
        } else {
                printPARules(\%Gaddress_groups, \%Gaddresses, \%address_groups, \%addresses, \%services, \%service_groups, \%applications, \%application_groups, \%tags, \%rules, \@parentRules);
        }
        undef @parentRules;
        exit;
}

if ($dump eq 'cpformat'){
        printCPformat(\%address_groups, \%addresses, \%services, \%service_groups);
        exit;
}

if (($debug) or ($dump)){

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' address objects? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $address (sort keys %addresses ) {
                        print "$address,";
                        if ($addresses{$address}{'ip'}){
                                print "$addresses{$address}{'ip'},";
                        }
                        if ($addresses{$address}{'cidr'}){
                                print "$addresses{$address}{'cidr'},";
                        }
                        if ($addresses{$address}{'comment'}){
                                print ",$addresses{$address}{'comment'},";
                        }
                        print "\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' address groups? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $group (sort keys %address_groups ) {
                        print "$group,";
                        printMembers(\@{$address_groups{$group}{'members'}});
                        if ($address_groups{$group}{'comment'}){
                                print ",$address_groups{$group}{'comment'}";
                        }
                        print "\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' application groups? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $group (sort keys %application_groups ) {
                        print "$group,";
                        printMembers(\@{$application_groups{$group}{'members'}});
                        if ($application_groups{$group}{'comment'}){
                                print ",$application_groups{$group}{'comment'}";
                        }
                        print "\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' services? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $service (sort keys %services ) {
                        print "$service,";
                        print "$services{$service}{'protocol'},";
                        print "$services{$service}{'port'}\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' service groups? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $group (sort keys %service_groups ) {
                        print "$group,";
                        printMembers(\@{$service_groups{$group}{'members'}});
                        if ($service_groups{$group}{'comment'}){
                                print ",$service_groups{$group}{'comment'}";
                        }
                        print "\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' tags and dynamic members? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $tag (sort keys %tags ) {
                        print "$tag,";
                        printMembers(\@{$tags{$tag}{'members'}});
                        if ($tags{$tag}{'comment'}){
                                print ",$tags{$tag}{'comment'}";
                        }
                        print "\n";
                }
        }

        if ($debug){
                print "DEBUG MODE: do you want to see \'$database\' rules (order preserved)? (y/n)\n";
                chomp ($_=<STDIN>);
        }
        if (($dump) or (/^y(es)?$/i)){
                foreach my $rule (keys %rules) {
                        push (@parentRules, $rule);
                }
                if ($database =~ /cma/){
                        printCPRules(\%address_groups, \%addresses, \%services, \%service_groups, \%exclGroups, \%rules, \@parentRules);
                } else {
                        printPARules(\%Gaddress_groups, \%Gaddresses, \%address_groups, \%addresses, \%services, \%service_groups, \%applications, \%application_groups, \%tags, \%rules, \@parentRules);
                }
                undef @parentRules;
        }

        if ($dump){
                exit;
        }
}

########################################################################################
#
# cli switches : --rule --itsec
#
########################################################################################


if ($rule){

        # determine object type provided
        my $objType;
        if (exists ($addresses{$rule})){
                $objType = "address";
                findParentGroups(\%address_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($address_groups{$rule})){
                $objType = "addressgrp";
                findParentGroups(\%address_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($services{$rule})){
                $objType = "service";
                findParentGroups(\%service_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($Gservices{$rule})){
                $objType = "service";
                findParentGroups(\%service_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($service_groups{$rule})){
                $objType = "servicegrp";
                findParentGroups(\%service_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($application_groups{$rule})){
                $objType = "appgrp";
                findParentGroups(\%application_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($exclGroups{$rule})){
                $objType = "exclgrp";
                findParentGroups(\%address_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($tags{$rule})){
                $objType = "tag";
                findParentGroups(\%address_groups, \@parentGroups, $rule, $objType);
        } elsif (exists ($appNames{$rule})){
                $objType = "appid";
                findParentGroups(\%application_groups, \@parentGroups, $rule, $objType);
        } elsif (is_ipv4($rule)) {
                if ($match){
                        # implicit match requested
                        $objType = "NETRE";
                } else {
                        # explicit match requested
                        $objType = "address";
                        my @matchedObjects;
                        findObjectFromIP(\%addresses, \@matchedObjects, $rule);
                        foreach my $objName (@matchedObjects){
                                findParentGroups(\%address_groups, \@parentGroups, $objName, $objType);
                        }
                        # find matching tag if any
                        foreach my $tag (sort keys %tags){
                                foreach my $member (@{$tags{$tag}{'members'}}) {
                                        if ($member eq $rule){
                                                findParentGroups(\%address_groups, \@parentGroups, $tag, "tag");
                                        }
                                }
                        }
                }
        }

        findParentRules(\%rules, \@parentRules, $rule, $objType);

        # corresponding static group to tags for ITSEC02163
        if (($itsec) and ($objType eq "tag")){
                $fh->open("<$inputDir/$tagItsecFile") or die "cannot open $inputDir/$tagItsecFile - $!";
                while(<$fh>) {
                        # GLOBAL-LEGACY_MGMT_ACS_HOSTS_ITSEC02163,x99MGMT-ACS_TAG
                        chomp($_);
                        my @data = split /\,/, $_;
                        if ($data[1] eq $rule){
                                push (@parentGroups, $data[0]);
                                if ($debug){
                                        print "DEBUG MODE: do you want to see \'$database\' ITSEC groups matching tag? (y/n)\n";
                                        chomp ($_=<STDIN>);
                                        if (/^y(es)?$/i){
                                                print "DEBUG : Tag $rule matched in group $data[0]\n";
                                        }
                                }
                        }
                }
                $fh->close();
        }

        foreach my $parentGroup (@parentGroups){
                findParentRules(\%rules, \@parentRules, $parentGroup, $objType);
        }

        my @unique_parentRules = do { my %seen; grep { !$seen{$_}++ } @parentRules };

        if ($database =~ /cma/){
                printCPRules(\%address_groups, \%addresses, \%services, \%service_groups, \%exclGroups, \%rules, \@unique_parentRules);
        } else {
                printPARules(\%Gaddress_groups, \%Gaddresses, \%address_groups, \%addresses, \%services, \%service_groups, \%applications, \%application_groups, \%tags, \%rules, \@unique_parentRules);
        }
        exit;
}

########################################################################################
#
# subroutines
#
########################################################################################

# s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
sub make_array_from_str {

    # take Python list in string format and return an arrays
    # e.g. ['nat-rule', 'pre-nat-rule', 'post-nat-rule']

    my $python_list_string = shift;
    my @data;

    if ($python_list_string){
        $python_list_string =~ s/[\[\]'\s]+//g; # remove bookends, whitespace and single quotes
        if ($python_list_string =~ /\,/){
            @data = split (/\,/, $python_list_string);
        } else {
            @data = $python_list_string;
        }
    }

    return @data;
}

sub readPaloAPIFormat{

    # have to do the objects first and then the rules as cannot figure out nested groups otherwise

    my ( $application_groups_ref, $address_groups_ref, $addresses_ref, $services_ref, $service_groups_ref, $tags_ref, $objFile, $dir ) = @_;
    # dbedit_processed_objects, dbedit_processed_pre_rules, dbedit_processed_post_rules
    my $csv_fields = 100;

    # set the fixed values for the numbered CSV fields
    my $vendor = 0;
    my $type = 1;
    my $location = 3;
    my $op_action = 2;
    my $name = 4;
    my $subtype = 5;
    my $members = 6;
    my $ip = 7;
    my $netmask = 8;
    my $cidr = 9;
    my $description = 10;
    my $color = 11;
    my $protocol = 12;
    my $source_port = 13;
    my $destination_port = 14;
    my $nexthop = 15;
    my $tag = 16;
    my $value = 17;
    my $interface = 18;
    my $enable_user_identification = 19;
    my $metric = 20;
    my $mgmt_profile = 21;
    my $zone = 22;
    my $rule_action = 23;
    my $application = 24;
    my $category = 25;
    my $data_filtering = 26;
    my $destination = 27;
    my $disable_server_response_inspection = 28;
    my $disabled = 29;
    my $file_blocking = 30;
    my $fromzone = 31;
    my $group = 32;
    my $hip_profiles = 33;
    my $icmp_unreachable = 34;
    my $log_end = 35;
    my $log_setting = 36;
    my $log_start = 37;
    my $negate_destination = 38;
    my $negate_source = 39;
    my $negate_target = 40;
    my $schedule = 41;
    my $service = 42;
    my $source = 43;
    my $source_user = 44;
    my $spyware = 45;
    my $target = 46;
    my $tozone = 47;
    my $url_filtering = 48;
    my $virus = 49;
    my $vulnerability = 50;
    my $wildfire_analysis = 51;
    my $destination_dynamic_translated_address = 52;
    my $destination_dynamic_translated_distribution = 53;
    my $destination_dynamic_translated_port = 54;
    my $destination_translated_address = 55;
    my $destination_translated_port = 56;
    my $ha_binding = 57;
    my $nat_type = 58;
    my $source_translation_address_type = 59;
    my $source_translation_fallback_interface = 60;
    my $source_translation_fallback_ip_address = 61;
    my $source_translation_fallback_ip_type = 62;
    my $source_translation_fallback_translated_addresses = 63;
    my $source_translation_fallback_type = 64;
    my $source_translation_interface = 65;
    my $source_translation_ip_address = 66;
    my $source_translation_static_bi_directional = 67;
    my $source_translation_static_translated_address = 68;
    my $source_translation_translated_addresses = 69;
    my $source_translation_type = 70;
    my $to_interface = 71;
    my $category = 72;
    my $subcategory = 73;
    my $technology = 74;
    my $risk = 75;
    my $evasive = 76;
    my $excessive_bandwidth_use = 77;
    my $prone_to_misuse = 78;
    my $is_saas = 79;
    my $transfers_files = 80;
    my $tunnels_other_apps = 81;
    my $used_by_malware = 82;
    my $has_known_vulnerabilities = 83;
    my $pervasive = 84;
    my $default_type = 85;
    my $parent_app = 86;
    my $timeout = 87;
    my $tcp_timeout = 88;
    my $udp_timeout = 89;
    my $tcp_half_closed_timeout = 90;
    my $tcp_time_wait_timeout = 91;
    my $tunnel_applications = 92;
    my $file_type_ident = 93;
    my $virus_ident = 94;
    my $data_ident = 95;
    my $default_port = 96;
    my $default_ip_protocol = 97;
    my $default_icmp_type = 98;
    my $default_icmp_code = 99;

    # Create the CSV object
    my $fh = new FileHandle;
    my $csv = Text::CSV_XS->new ({ binary => 1, auto_diag => 1 });
    open my $fh, "<:encoding(utf8)", "$dir/$objFile" or die "Cannot open $objFile: $!";
    $csv->column_names ($csv->getline ($fh));

    #while (my $href = $csv->getline_hr ($fh)) {
    while ( my $row = $csv->getline($fh) ) {
        # convert certain fields into arrays
        $row->[$members] = make_array_from_str($row->[$members]);
        $row->[$tag] = make_array_from_str($row->[$tag]);
        $row->[$value] = make_array_from_str($row->[$value]);
        if ($row->[$location] =~ /__/){
            $row->[$location] = (split /__/, $row->[$location])[0];
        }
        #if ($href->{objtype} eq "address"){
        if ($row->[$type] eq 'address'){
            $$addresses_ref{$row->[$name]} = $row->[$name];
            $$addresses_ref{$row->[$name]}{'description'} = $row->[$description];
            $$addresses_ref{$row->[$name]}{'type'} = $row->[$subtype];
            $$addresses_ref{$row->[$name]}{'tag'} = $data[$tag];
            if ($row->[$subtype] eq 'ip-netmask'){
                $$addresses_ref{$row->[$name]}{'cidr'} = $row->[$cidr];
                if ($row->[$cidr] =~ /\//){
                    my $ip = (split /\//, $row->[$cidr])[0];
                    my $bits = (split /\//, $row->[$cidr])[1];
                    $$addresses_ref{$row->[$name]}{'ip'} = $ip;
                    $$addresses_ref{$row->[$name]}{'netmask'} = $netbits{$bits};
                }
            } else {
                $$addresses_ref{$row->[$name]}{'value'} = $row->[$value];
                # could run nslookup here on fqdn objects?
            }
        } elsif ($row->[$type] eq 'address-group'){
            $$address_groups_ref{$row->[$name]}{'name'} = $row->[$name];
            $$address_groups_ref{$row->[$name]}{'description'} = $row->[$description];
            if ($row->[$subtype] eq 'dynamic'){
                $$address_groups_ref{$row->[$name]}{'tags'} = $row->[$value];
            } elsif ($row->[$subtype] eq 'static'){
                if (!$row->[$members]){
                    push @{ $$address_groups_ref{$row->[$name]}{'members'}}, 'placeholder';
                } else {
                    $$address_groups_ref{$row->[$name]}{'members'} = $row->[$members];
                }
            }
        } elsif ($row->[$type] eq 'service'){
            $$services_ref{$row->[$name]}{'name'} = $row->[$name];
            $$services_ref{$row->[$name]}{'protocol'} = $row->[$protocol];
            $$services_ref{$row->[$name]}{'sport'} = $row->[$source_port];
            $$services_ref{$row->[$name]}{'dport'} = $row->[$destination_port];
            $$services_ref{$row->[$name]}{'description'} = $row->[$description];
            $$services_ref{$row->[$name]}{'tag'} = $row->[$tag];
        } elsif ($row->[$type] eq 'service-group'){
            $$service_groups_ref{$row->[$name]}{'name'} = $row->[$name];
            $$service_groups_ref{$row->[$name]}{'members'} = $row->[$members];
            $$service_groups_ref{$row->[$name]}{'tag'} = $row->[$tag];
        } elsif ($row->[$type] eq 'tag'){
            $$tags_ref{$row->[$name]}{'name'} = $row->[$name];
            $$tags_ref{$row->[$name]}{'description'} = $row->[$description];
        } elsif ($row->[$type] eq 'dip'){
            foreach my $member ($row->[$members]){
                $$dips_ref{$row->[$name]}{'name'} = join('__', $member, $row->[$tag]);
                $$dips_ref{$row->[$name]}{'ip'} = $member;
                $$dips_ref{$row->[$name]}{'tag'} = $row->[$tag];
            }
        } elsif ($row->[$type] eq 'route'){
            $$staticRoutes_ref{$row->[$name]}{'name'} = $row->[$name];
            $$staticRoutes_ref{$row->[$name]}{'destination'} = $row->[$cidr];
            $$staticRoutes_ref{$row->[$name]}{'nexthop_type'} = $row->[$subtype];
            $$staticRoutes_ref{$row->[$name]}{'nexthop'} = $row->[$nexthop];
            $$staticRoutes_ref{$row->[$name]}{'interface'} = $row->[$interface];
            $$staticRoutes_ref{$row->[$name]}{'admin_dist'} = $row->[$admin_dist];
            $$staticRoutes_ref{$row->[$name]}{'metric'} = $row->[$metric];
        } elsif ($row->[$type] eq 'application'){
            $row->[$tunnel_applications] = make_array_from_str($row->[$tunnel_applications]);
            $row->[$default_port] = make_array_from_str($row->[$default_port]);
            $$applications_ref{$row->[$name]}{'name'} = $row->[$name];
            $$applications_ref{$row->[$name]}{'description'} = $row->[$description];
            $$applications_ref{$row->[$name]}{'category'} = $row->[$category];
            $$applications_ref{$row->[$name]}{'subcategory'} = $row->[$subcategory];
            $$applications_ref{$row->[$name]}{'technology'} = $row->[$technology];
            $$applications_ref{$row->[$name]}{'risk'} = $row->[$risk];
            $$applications_ref{$row->[$name]}{'default_type'} = $row->[$default_type];
            $$applications_ref{$row->[$name]}{'default_port'} = $row->[$default_port];
            $$applications_ref{$row->[$name]}{'default_ip_protocol'} = $row->[$default_ip_protocol];
            $$applications_ref{$row->[$name]}{'default_icmp_type'} = $row->[$default_icmp_type];
            $$applications_ref{$row->[$name]}{'default_icmp_code'} = $row->[$default_icmp_code];
            $$applications_ref{$row->[$name]}{'parent_app'} = $row->[$parent_app];
            $$applications_ref{$row->[$name]}{'timeout'} = $row->[$timeout];
            $$applications_ref{$row->[$name]}{'tcp_timeout'} = $row->[$tcp_timeout];
            $$applications_ref{$row->[$name]}{'udp_timeout'} = $row->[$udp_timeout];
            $$applications_ref{$row->[$name]}{'tcp_half_closed_timeout'} = $row->[$tcp_half_closed_timeout];
            $$applications_ref{$row->[$name]}{'tcp_time_wait_timeout'} = $row->[$tcp_time_wait_timeout];
            $$applications_ref{$row->[$name]}{'evasive_behavior'} = $row->[$evasive];
            $$applications_ref{$row->[$name]}{'consume_big_bandwidth'} = $row->[$excessive_bandwidth_use];
            $$applications_ref{$row->[$name]}{'used_by_malware'} = $row->[$used_by_malware];
            $$applications_ref{$row->[$name]}{'able_to_transfer_file'} = $row->[$transfers_files];
            $$applications_ref{$row->[$name]}{'tunnel_applications'} = $row->[$tunnel_applications];
            $$applications_ref{$row->[$name]}{'has_known_vulnerability'} = $row->[$has_known_vulnerabilities];
            $$applications_ref{$row->[$name]}{'tunnel_other_application'} = $row->[$tunnels_other_apps];
            $$applications_ref{$row->[$name]}{'prone_to_misuse'} = $row->[$prone_to_misuse];
            $$applications_ref{$row->[$name]}{'file_type_ident'} = $row->[$file_type_ident];
            $$applications_ref{$row->[$name]}{'pervasive_use'} = $row->[$pervasive];
            $$applications_ref{$row->[$name]}{'virus_ident'} = $row->[$virus_ident];
            $$applications_ref{$row->[$name]}{'data_ident'} = $row->[$data_ident];
            $$applications_ref{$row->[$name]}{'tag'} = $row->[$tag];
        } elsif ($row->[$type] eq 'application-group'){
            #o = ApplicationGroup(name=row[name], value=row[members], tag=row[tag])
            $$application_groups_ref{$row->[$name]} = $row->[$name];
            $$application_groups_ref{$row->[$name]}{'members'},  $row->[$members];
            $$application_groups_ref{$row->[$name]}{'tag'} = $row->[$tag];
        } elsif ($row->[$type] =~ /[(pre|post)-]?security-rule/){
            $row->[$application] = make_array_from_str($row->[$application]);
            $row->[$category] = make_array_from_str($row->[$category]);
            $row->[$destination] = make_array_from_str($row->[$destination]);
            $row->[$fromzone] = make_array_from_str($row->[$fromzone]);
            $row->[$hip_profiles] = make_array_from_str($row->[$hip_profiles]);
            $row->[$service] = make_array_from_str($row->[$service]);
            $row->[$source] = make_array_from_str($row->[$source]);
            $row->[$source_user] = make_array_from_str($row->[$source_user]);
            $row->[$target] = make_array_from_str($row->[$target]);
            $row->[$tozone] = make_array_from_str($row->[$tozone]);

            $$rules_ref{$row->[$name]}{'name'} = $row->[$name];
            $$rules_ref{$row->[$name]}{'srczone'} = $row->[$fromzone];
            $$rules_ref{$row->[$name]}{'srcaddr'}, $row->[$source];

            my @ruleNets;
            if ($data[$srcaddr] !~ /any/i){
                    foreach my $srcObj (@{ $$rules_ref{$data[$name]}{'srcaddr'}}){
                            if ($srcObj =~ /^G_/){
                                    printMembersExpanded(\@{$$Gaddress_groups_ref{$srcObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                            } else {
                                    printMembersExpanded(\@{$$address_groups_ref{$srcObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                            }
                    }
            }
            $$rules_ref{$row->[$name]}{'srcuser'}, $row->[$source_user];
            $$rules_ref{$row->[$name]}{'dstzone'} = $row->[$tozone];
            $$rules_ref{$row->[$name]}{'dstaddr'},  $row->[$destination];

            if ($data[$dstaddr] !~ /any/i){
                    foreach my $dstObj (@{ $$rules_ref{$data[$name]}{'dstaddr'}}){
                            if ($dstObj =~ /^G_/){
                                    printMembersExpanded(\@{$$Gaddress_groups{$dstObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                            } else {
                                    printMembersExpanded(\@{$$address_groups{$dstObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                            }
                    }
            }
            # create re of src/dst nets for this rule
            if (@ruleNets){
                    $$rules_ref{$data[$name]}{'ruleNetsre'} = create_iprange_regexp_depthfirst(@ruleNets);
            }
            $$rules_ref{$row->[$name]}{'application'},  $row->[$application];
            $$rules_ref{$row->[$name]}{'service'},  $row->[$service];
            $$rules_ref{$row->[$name]}{'hip'} = $row->[$hip_profiles];
            $$rules_ref{$row->[$name]}{'url'} = $row->[$url_filtering];
            $$rules_ref{$row->[$name]}{'action'} = $row->[$rule_action];
            $$rules_ref{$row->[$name]}{'description'} = $row->[$description];
            $$rules_ref{$row->[$name]}{'tag'} = $row->[$tag];
            $$rules_ref{$row->[$name]}{'category'} = $row->[$category];
            $$rules_ref{$row->[$name]}{'data_filtering'} = $row->[$data_filtering];
            $$rules_ref{$row->[$name]}{'disable_server_response_inspection'} = $row->[$disable_server_response_inspection];
            $$rules_ref{$row->[$name]}{'disabled'} = $row->[$disabled];
            $$rules_ref{$row->[$name]}{'file_blocking'} = $row->[$file_blocking];
            $$rules_ref{$row->[$name]}{'group'} = $row->[$group];
            $$rules_ref{$row->[$name]}{'icmp_unreachable'} = $row->[$icmp_unreachable];
            $$rules_ref{$row->[$name]}{'log_end'} = $row->[$log_end];
            $$rules_ref{$row->[$name]}{'log_setting'} = $row->[$log_setting];
            $$rules_ref{$row->[$name]}{'log_start'} = $row->[$log_start];
            $$rules_ref{$row->[$name]}{'negate_destination'} = $row->[$negate_destination];
            $$rules_ref{$row->[$name]}{'negate_source'} = $row->[$negate_source];
            $$rules_ref{$row->[$name]}{'negate_target'} = $row->[$negate_target];
            $$rules_ref{$row->[$name]}{'schedule'} = $row->[$schedule];
            $$rules_ref{$row->[$name]}{'spyware'} = $row->[$spyware];
            $$rules_ref{$row->[$name]}{'target'} = $row->[$target];
            $$rules_ref{$row->[$name]}{'type'} = $row->[$subtype];
            $$rules_ref{$row->[$name]}{'virus'} = $row->[$virus];
            $$rules_ref{$row->[$name]}{'vulnerability'} = $row->[$vulnerability];
            $$rules_ref{$row->[$name]}{'wildfire_analysis'} = $row->[$wildfire_analysis];

          } elsif ($row->[$type] =~ /[(pre|post)-]?nat-rule/){

            $row->[$destination] = make_array_from_str($row->[$destination]);
            $row->[$fromzone] = make_array_from_str($row->[$fromzone]);
            $row->[$source] = make_array_from_str($row->[$source]);
            $row->[$source_translation_fallback_translated_addresses] = make_array_from_str($row->[$source_translation_fallback_translated_addresses]);
            $row->[$source_translation_translated_addresses] = make_array_from_str($row->[$source_translation_translated_addresses]);
            $row->[$target] = make_array_from_str($row->[$target]);
            $row->[$tozone] = make_array_from_str($row->[$tozone]);

            $$nats_ref{$row->[$name]}{'name'} = $row->[$name];
            $$nats_ref{$row->[$name]}{'description'} = $row->[$description];
            $$nats_ref{$row->[$name]}{'destination'} = $row->[$destination];
            $$nats_ref{$row->[$name]}{'destination_dynamic_translated_address'} = $row->[$destination_dynamic_translated_address];
            $$nats_ref{$row->[$name]}{'destination_dynamic_translated_distribution'} = $row->[$destination_dynamic_translated_distribution];
            $$nats_ref{$row->[$name]}{'destination_dynamic_translated_port'} = $row->[$destination_dynamic_translated_port];
            $$nats_ref{$row->[$name]}{'destination_translated_address'} = $row->[$destination_translated_address];
            $$nats_ref{$row->[$name]}{'destination_translated_port'} = $row->[$destination_translated_port];
            $$nats_ref{$row->[$name]}{'disabled'} = $row->[$disabled];
            $$nats_ref{$row->[$name]}{'fromzone'} = $row->[$fromzone];
            $$nats_ref{$row->[$name]}{'ha_binding'} = $row->[$ha_binding];
            $$nats_ref{$row->[$name]}{'nat_type'} = $row->[$nat_type];
            $$nats_ref{$row->[$name]}{'negate_target'} = $row->[$negate_target];
            $$nats_ref{$row->[$name]}{'service'} = $row->[$service];
            $$nats_ref{$row->[$name]}{'source'} = $row->[$source];
            $$nats_ref{$row->[$name]}{'source_translation_address_type'} = $row->[$source_translation_address_type];
            $$nats_ref{$row->[$name]}{'source_translation_fallback_interface'} = $row->[$source_translation_fallback_interface];
            $$nats_ref{$row->[$name]}{'source_translation_fallback_ip_address'} = $row->[$source_translation_fallback_ip_address];
            $$nats_ref{$row->[$name]}{'source_translation_fallback_ip_type'} = $row->[$source_translation_fallback_ip_type];
            $$nats_ref{$row->[$name]}{'source_translation_fallback_translated_addresses'} = $row->[$source_translation_fallback_translated_addresses];
            $$nats_ref{$row->[$name]}{'source_translation_fallback_type'} = $row->[$source_translation_fallback_type];
            $$nats_ref{$row->[$name]}{'source_translation_interface'} = $row->[$source_translation_interface];
            $$nats_ref{$row->[$name]}{'source_translation_ip_address'} = $row->[$source_translation_ip_address];
            $$nats_ref{$row->[$name]}{'source_translation_static_bi_directional'} = $row->[$source_translation_static_bi_directional];
            $$nats_ref{$row->[$name]}{'source_translation_static_translated_address'} = $row->[$source_translation_static_translated_address];
            $$nats_ref{$row->[$name]}{'source_translation_translated_addresses'} = $row->[$source_translation_translated_addresses];
            $$nats_ref{$row->[$name]}{'source_translation_type'} = $row->[$source_translation_type];
            $$nats_ref{$row->[$name]}{'tag'} = $row->[$tag];
            $$nats_ref{$row->[$name]}{'target'} = $row->[$target];
            $$nats_ref{$row->[$name]}{'to_interface'} = $row->[$interface];
            $$nats_ref{$row->[$name]}{'tozone'} = $row->[$tozone];
        }
    }
    $fh->close();
}

sub readPARules (\$\$\%\%\%\%\%\%) {

        my $objFile = shift;
        my $dgDir = shift;
        my $rules_ref = shift;
        my $address_groups_ref = shift;
        my $addresses_ref = shift;
        my $tags_ref = shift;
        my $Gaddress_groups_ref = shift;
        my $Gaddresses_ref = shift;

        # set fields from .rules file
        my $name = "0";
        my $type = "1";
        my $srczone = "2";
        my $srcaddr = "3";
        my $srcuser = "4";
        my $dstzone = "5";
        my $dstaddr = "6";
        my $app = "7";
        my $service = "8";
        my $hip = "9";
        my $url = "10";
        my $ruletype = "11";
        my $logstart = "12";
        my $disabled = "13";
        my $action = "14";
        my $tagfield = "15";
        my $description = "16";

        my $fh = new FileHandle;
        $fh->open("<$dgDir/$objFile") or die "cannot open $dgDir/$objFile - $!";
        while(<$fh>) {
                chomp($_);
                my @data = split /\,/, $_;
                if ($data[$type] eq 'rule'){
                        # DCAG Pool User Drop Restricted,rule,[MGT],[G_GLOBAL-DCAG_POOL_NETWORKS],[any],[ENAP|ISG_VPN],[GLOBAL-DCAG_RESTRICTED_NETWORKS],[any],[any],[any],[any],,,,drop,,
                        next if ($data[$disabled] eq "yes");
                        next if (!$data[$srczone]);

                        $$rules_ref{$data[$name]}{'name'} = $data[$name];
                        $$rules_ref{$data[$name]}{'srczone'} = $data[$srczone];
                        $data[$srcaddr] =~ s/^\[|\]$//g; # remove bookends
                        if ($data[$srcaddr] =~ /\|/ ){
                                my @members = split /\|/, $data[$srcaddr];
                                foreach (@members){
                                        push @{ $$rules_ref{$data[$name]}{'srcaddr'}}, $_;
                                }
                        } else {
                                push @{ $$rules_ref{$data[$name]}{'srcaddr'}}, $data[$srcaddr];
                        }
                        my @ruleNets;
                        if ($data[$srcaddr] !~ /any/i){
                                foreach my $srcObj (@{ $$rules_ref{$data[$name]}{'srcaddr'}}){
                                        if ($srcObj =~ /^G_/){
                                                printMembersExpanded(\@{$$Gaddress_groups_ref{$srcObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                        } else {
                                                printMembersExpanded(\@{$$address_groups_ref{$srcObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                        }
                                }
                        }
                        $data[$srcuser] =~ s/^\[|\]$//g; # remove bookends
                        if ($data[$srcuser] =~ /\|/ ){
                                @members = split /\|/, $data[$srcuser];
                                foreach (@members){
                                        push @{ $$rules_ref{$data[$name]}{'srcuser'}}, $_;
                                }
                        } else {
                                push @{ $$rules_ref{$data[$name]}{'srcuser'}}, $data[$srcuser];
                        }
                        $$rules_ref{$data[$name]}{'dstzone'} = $data[$dstzone];
                        $data[$dstaddr] =~ s/^\[|\]$//g; # remove bookends
                        if ($data[$dstaddr] =~ /\|/ ){
                                @members = split /\|/, $data[$dstaddr];
                                foreach (@members){
                                        push @{ $$rules_ref{$data[$name]}{'dstaddr'}}, $_;
                                }
                        } else {
                                push @{ $$rules_ref{$data[$name]}{'dstaddr'}},  $data[$dstaddr];
                        }
                        if ($data[$dstaddr] !~ /any/i){
                                foreach my $dstObj (@{ $$rules_ref{$data[$name]}{'dstaddr'}}){
                                        if ($dstObj =~ /^G_/){
                                                printMembersExpanded(\@{$$Gaddress_groups{$dstObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                        } else {
                                                printMembersExpanded(\@{$$address_groups{$dstObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                        }
                                }
                        }
                        # create re of src/dst nets for this rule
                        if (@ruleNets){
                                $$rules_ref{$data[$name]}{'ruleNetsre'} = create_iprange_regexp_depthfirst(@ruleNets);
                        }
                        $data[$app] =~ s/^\[|\]$//g; # remove bookends
                        if ($data[$app] =~ /\|/ ){
                                @members = split /\|/, $data[$app];
                                foreach (@members){
                                        push @{ $$rules_ref{$data[$name]}{'application'}},  $_;
                                }
                        } else {
                                push @{ $$rules_ref{$data[$name]}{'application'}},  $data[$app];
                        }
                        $data[$service] =~ s/^\[|\]$//g; # remove bookends
                        if ($data[$service] =~ /\|/ ){
                                @members = split /\|/, $data[$service];
                                foreach (@members){
                                        push @{ $$rules_ref{$data[$name]}{'service'}},  $_;
                                }
                        } else {
                                push @{ $$rules_ref{$data[$name]}{'service'}},  $data[$service];
                        }
                        if ($data[$hip]){
                                $$rules_ref{$data[$name]}{'hip'} = $data[$hip];
                        }
                        if ($data[$url]){
                                $$rules_ref{$data[$name]}{'url'} = $data[$url];
                        }
                        if ($data[$ruletype]){
                                $$rules_ref{$data[$name]}{'ruletype'} = $data[$ruletype];
                        }
                        if ($data[$logstart]){
                                $$rules_ref{$data[$name]}{'logstart'} = $data[$logstart];
                        }
                        if ($data[$disabled]){
                                $$rules_ref{$data[$name]}{'disabled'} = $data[$disabled];
                        }
                        if ($data[$action]){
                                $$rules_ref{$data[$name]}{'action'} = $data[$action];
                        }
                        if ($data[$tagfield]){
                                $rules{$data[$name]}{'tag'} = $data[$tagfield];
                        }
                        if ($data[$description]){
                                $rules{$data[$name]}{'description'} = $data[$description];
                        }
                }
        }
        $fh->close();
}

sub readCPRules (\$\$\%\%\%\%\%\%\%) {

        my $cma = shift;
        my $cmaDir = shift;
        my $rules_ref = shift;
        my $address_groups_ref = shift;
        my $addresses_ref = shift;
        my $tags_ref = shift;
        my $Gaddress_groups_ref = shift;
        my $Gaddresses_ref = shift;
        my $exclGroups_ref = shift;

        # get list of '*.sec' files for this CMA
        opendir (DIR, "$cmaDir" ) or die $!;
        my @policies = grep { $_ =~ /$cma.*\.sec$/  } readdir DIR;
        closedir(DIR);
        if ($debug){
                print "DEBUG MODE: CMA \'$cma\' found ", join("______", @policies), "\n";
        }

        # set fields from .sec file
        my $ruletype = "0";
        my $rulename = "1";
        my $source = "2";
        my $destination = "3";
        my $vpn = "4";
        my $service = "5";
        my $action = "6";
        my $track = "7";
        my $target = "8";
        my $time  = "9";
        my $comment = "10";
        my $location = "11";

        foreach my $policy (@policies){
                my $rulenumber = 0;
                my $fh = new FileHandle;
                $fh->open("<$cmaDir/$policy") or die "cannot open $cmaDir/$policy - $!";
                while(<$fh>) {
                        chomp($_);
                        my @data = split /\;/, $_;
                        # remove all leading/trailing whitespace or bang from each array element
                        s{^\s+|\s+$|\!}{}g foreach @data;
                        if ($data[$ruletype] eq 'security_rule: Rule'){
                                $rulenumber++;
                                $data[$rulename] = join("-", $policy, $rulenumber, $data[$rulename]);
                                $$rules_ref{$data[$rulename]}{'name'} = $data[$rulename];
                                if ($data[$source] =~ /\,/ ){
                                        my @members = split /\,/, $data[$source];
                                        s{^\s+|\s+$|\!}{}g foreach @members;
                                        foreach my $member (@members){
                                                # user rules have @ symbol! RAM-NID-SecurityUsers@SMA-JUMPBOX_SERVERS
                                                if ($member =~ /\@/){
                                                        $member = (split /\@/, $member)[1];
                                                }
                                                push @{ $$rules_ref{$data[$rulename]}{'srcaddr'}}, $member;
                                        }
                                } else {
                                        # user rules have @ symbol! RAM-NID-SecurityUsers@SMA-JUMPBOX_SERVERS
                                        if ($data[$source] =~ /\@/){
                                                $data[$source] = (split /\@/, $data[$source])[1];
                                        }
                                        push @{ $$rules_ref{$data[$rulename]}{'srcaddr'}}, $data[$source];
                                }
                                my @ruleNets;
                                if ($data[$source] ne 'Any'){
                                        foreach my $srcObj (@{ $$rules_ref{$data[$rulename]}{'srcaddr'}}){
                                                if (exists($$address_groups_ref{$srcObj})){
                                                        # add into @ruleNets all the members of the group
                                                        printMembersExpanded(\@{$$address_groups_ref{$srcObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                                } elsif (exists($$exclGroups_ref{$srcObj})){
                                                        # array of delta networks already exists for exclusion group
                                                        if (exists($$exclGroups_ref{$srcObj}{'delta'})){
                                                                splice @ruleNets, 1, 0, @{ $$exclGroups_ref{$srcObj}{'delta'}};
                                                        }
                                                } else {
                                                        push (@ruleNets, $$addresses_ref{$srcObj}{'cidr'});
                                                }
                                        }
                                }
                                if ($data[$destination] =~ /\,/ ){
                                        my @members = split /\,/, $data[$destination];
                                        s{^\s+|\s+$|\!}{}g foreach @members;
                                        foreach my $member (@members){
                                                push @{ $$rules_ref{$data[$rulename]}{'dstaddr'}}, $member;
                                        }
                                } else {
                                        push @{ $$rules_ref{$data[$rulename]}{'dstaddr'}}, $data[$destination];
                                }
                                if ($data[$destination] ne 'Any'){
                                        foreach my $dstObj (@{ $$rules_ref{$data[$rulename]}{'dstaddr'}}){
                                                if (exists($$address_groups_ref{$dstObj})){
                                                        printMembersExpanded(\@{$$address_groups_ref{$dstObj}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, 2, \@ruleNets, \%{$tags_ref});
                                                } elsif (exists($$exclGroups_ref{$dstObj})){
                                                        if (exists($$exclGroups_ref{$dstObj}{'delta'})){
                                                                splice @ruleNets, 1, 0, @{ $$exclGroups_ref{$dstObj}{'delta'}};
                                                        }
                                                } else {
                                                        push (@ruleNets, $$addresses_ref{$dstObj}{'cidr'});
                                                }
                                        }
                                }
                                # create re of src/dst nets for this rule
                                if (@ruleNets){
                                        my @unique_ruleNets;
                                        @unique_ruleNets = do { my %seen; grep { !$seen{$_}++ } @ruleNets };
                                        # all members of @unique_ruleNets must be in cidr notation
                                        # foreach (@unique_ruleNets){ print "$data[$rulename] $_\n"; }
                                        $$rules_ref{$data[$rulename]}{'ruleNetsre'} = create_iprange_regexp_depthfirst(@unique_ruleNets);
                                }
                                undef @ruleNets;
                                undef @unique_ruleNets;
                                $$rules_ref{$data[$rulename]}{'vpn'} = $data[$vpn];
                                if ($data[$service] =~ /\,/ ){
                                        my @members = split /\,/, $data[$service];
                                        s{^\s+|\s+$}{}g foreach @members;
                                        foreach my $member (@members){
                                                push @{ $$rules_ref{$data[$rulename]}{'service'}}, $member;
                                        }
                                } else {
                                        push @{ $$rules_ref{$data[$rulename]}{'service'}}, $data[$service];
                                }
                                $$rules_ref{$data[$rulename]}{'action'} = $data[$action];
                                $$rules_ref{$data[$rulename]}{'track'} = $data[$track];
                                if ($data[$target] =~ /\,/ ){
                                        my @members = split /\,/, $data[$target];
                                        s{^\s+|\s+$}{}g foreach @members;
                                        foreach my $member (@members){
                                                push @{ $$rules_ref{$data[$rulename]}{'target'}}, $member;
                                        }
                                } else {
                                        push @{ $$rules_ref{$data[$rulename]}{'target'}},  $data[$target];
                                }
                                $$rules_ref{$data[$rulename]}{'time'} = $data[$time];
                                $$rules_ref{$data[$rulename]}{'description'} = $data[$comment];
                                $$rules_ref{$data[$rulename]}{'location'} = $data[$location];
                        }
                }
                $fh->close();
        }
}

sub readCPObjects {

        my ( $exclGroups_ref, $address_groups_ref, $addresses_ref, $services_ref, $service_groups_ref, $objFile, $dir ) = @_;

        my $name = "0";
        my $type = "1";
        my $protocol = "1";
        my $objmembers = "2";
        my $ip = "2";
        my $incl = "2";
        my $excl = "3";
        my $mask = "3";
        my $timeout = "3";
        my $port = "3";
        my $colour = "4";
        my $comment = "8";
        my $fh = new FileHandle;

        $fh->open("<$dir/$objFile") or die "cannot open $dir/$objFile - $!";
        while(<$fh>) {
                chomp($_);
                my @data = split /\,/, $_;
                if ($data[$type] eq 'srvgroup'){
                        # gIntegrity_Server,srvgroup,gZSP,,black,,,,"Accessing Integrity Server from SecureClient"
                        # gIntegrity_Server,srvgroup,gHTTP_wo_SCV,,black,,,,"Accessing Integrity Server from SecureClient"
                        $$service_groups_ref{$data[$name]} = $data[$name];
                        $$service_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$service_groups_ref{$data[$name]}{'colour'} = $data[$colour];
                        push @{ $$service_groups_ref{$data[$name]}{'members'}},  $data[$objmembers];
                } elsif (($data[$type] eq 'group') or ($data[$type] eq 'emptygrp')){
                        # G_OCDS-00DCMC_NETWORKS,group,G_OCDS-00DCMC_10.242.129.224m27,,magenta,,,,"Security Zone 00 Core"
                        # G_OCDS-00DCMC_NETWORKS,group,G_OCDS-00DCMC_10.242.139.0m24,,magenta,,,,"Security Zone 00 Core"
                        $$address_groups_ref{$data[$name]} = $data[$name];
                        $$address_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$address_groups_ref{$data[$name]}{'colour'} = $data[$colour];
                        push @{ $$address_groups_ref{$data[$name]}{'members'}}, $data[$objmembers];
                } elsif ($data[$type] eq 'exclgrp'){
                        # G_GLOBAL-ENT_NETWORKS,exclgrp,G_GLOBAL-ENT_NETWORKS_INCL,G_GLOBAL-ENT_NETWORKS_EXCL,red,,,,Processed_by_Object_Dumper_v2.4
                        $$exclGroups_ref{$data[$name]} = $data[$name];
                        $$exclGroups_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$exclGroups_ref{$data[$name]}{'colour'} = $data[$colour];
                        $$exclGroups_ref{$data[$name]}{'incl'} = $data[$incl];
                        $$exclGroups_ref{$data[$name]}{'excl'} = $data[$excl];
                } elsif (($data[$type] eq 'host') or ($data[$type] eq 'net') or ($data[$type] eq 'ss')){
                        # G_ocdp-nsfw600-cluster-CT,host,10.242.49.86,255.255.255.255,magenta,,,,"OCD ISG CT Cluster VIP"
                        # G_OCDS-VA_CT_10.242.128.88_m29,net,10.242.128.88,255.255.255.248,magenta,,,,"OCD PRE PROD VA LAN"
                        $$addresses_ref{$data[$name]} = $data[$name];
                        $$addresses_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$addresses_ref{$data[$name]}{'colour'} = $data[$colour];
                        $$addresses_ref{$data[$name]}{'netmask'} = $data[$mask];
                        $$addresses_ref{$data[$name]}{'cidr'} = join ('/', $data[$ip], $netmasks{$data[$mask]});
                        $$addresses_ref{$data[$name]}{'ip'} = $data[$ip];
                } elsif (($data[$type] eq 'tcp') or ($data[$type] eq 'udp') or ($data[$type] eq 'icmp') or ($data[$type] eq 'other')){
                        # G_TCP-1414_8h,tcp,1414,28800,black,,,default,"long TCP timeoute
                        # gUA_CS,udp,32640,default,black,replies,,default,
                        # gicmp-proto,other,1,default,Dark Orchid,noreplies,nomatch,,"Internet Control Message Protocol"
                        # gecho-reply,icmp,0,255.255.255.255,Dark Orchid,,,,"ICMP, echo reply"
                        $$services_ref{$data[$name]} = $data[$name];
                        $$services_ref{$data[$name]}{'protocol'} = $data[$protocol];
                        $$services_ref{$data[$name]}{'port'} = $data[$port];
                        $$services_ref{$data[$name]}{'timeout'} = $data[$timeout];
                        $$services_ref{$data[$name]}{'colour'} = $data[$colour];
                        $$services_ref{$data[$name]}{'comment'} = $data[$comment];
                } elsif ($data[$type] eq 'domain'){
                        # domain objects
                        # .emea.nid.prod.sma,domain,,,black,,,,
                        $$addresses_ref{$data[$name]} = $data[$name];
                        $$addresses_ref{$data[$name]}{'colour'} = $data[$colour];
                        $$addresses_ref{$data[$name]}{'ip'} = "169.254.254.254";
                        $$addresses_ref{$data[$name]}{'netmask'} = "255.255.255.255";
                        $$addresses_ref{$data[$name]}{'cidr'} = "169.254.254.254/32";
                }
        }
        $fh->close();

        # populate exclGroups with delta regexp - need to swap between object types for functionality
        my %empty = ();
        foreach my $parentGroup (keys %$exclGroups_ref){

                my @inclNets;
                my @exclNets;
                my @exclNetNetmasks;
                my @inclNetAddrs;
                my @exclNetAddrs;
                my @deltaNets;
                my @unique_deltaNets;
                my $inclGroup = $$exclGroups_ref{$parentGroup}{'incl'};
                my $exclGroup = $$exclGroups_ref{$parentGroup}{'excl'};

                # populate arrays with group contents
                printMembersExpanded(\@{$$address_groups_ref{$inclGroup}{'members'}}, \%{$address_groups_ref}, \%empty, \%{$addresses_ref}, \%empty, 2, \@inclNets, \%empty);
                printMembersExpanded(\@{$$address_groups_ref{$exclGroup}{'members'}}, \%{$address_groups_ref}, \%empty, \%{$addresses_ref}, \%empty, 2, \@exclNets, \%empty);

                # some of the groups are empty!
                foreach my $net (@inclNets){
                        push @inclNetAddrs, NetAddr::IP->new($net);
                }

                foreach my $net (@exclNets){
                        push @exclNetAddrs, NetAddr::IP->new($net);
                }

                #print "$parentGroup - $inclGroup - $exclGroup\n";
                if ((!@exclNets) and (@inclNets)){
                        @unique_deltaNets = @inclNets;
                } elsif ((@exclNets) and (!@inclNets)){
                        @unique_deltaNets = @exclNets;
                } elsif (!(@exclNets) and (!@inclNets)){
                        undef @unique_deltaNets;
                } else {
                        foreach my $net (NetAddr::IP::compact(@exclNetAddrs)) {
                                push @exclNetNetmasks, Net::Netmask->new($net->cidr());
                        }

                        foreach my $net (NetAddr::IP::compact(@inclNetAddrs)) {
                                my $inclNetNetmask = Net::Netmask->new($net->cidr());
                                foreach my $net (cidrs2inverse($inclNetNetmask, @exclNetNetmasks)){
                                        push @deltaNets, NetAddr::IP->new($net->desc());
                                }
                        }

                        foreach my $net (NetAddr::IP::compact(@deltaNets)) {
                                push (@unique_deltaNets, $net->cidr());
                        }
                }


                if (@unique_deltaNets){
                        $$exclGroups_ref{$parentGroup}{'objre'} = create_iprange_regexp_depthfirst(@unique_deltaNets);
                        @{ $$exclGroups_ref{$parentGroup}{'delta'}} = @unique_deltaNets;
                } else {
                        $$exclGroups_ref{$parentGroup}{'objre'} = "null";
                }
        }
}

sub readPAObjects {

        my ( $application_groups_ref, $address_groups_ref, $addresses_ref, $services_ref, $service_groups_ref, $tags_ref, $objFile, $dir ) = @_;

        my $name = "0";
        my $type = "1";
        my $comment = "2";
        my $protocol = "2";
        my $objmembers = "3";
        my $cidr = "3";
        my $port = "3";
        my $ip = "3";
        my $tag = "5";
        my $fh = new FileHandle;

        $fh->open("<$dir/$objFile") or die "cannot open $dir/$objFile - $!";
        while(<$fh>) {
                chomp($_);
                my @data = split /\,/, $_;
                $data[$objmembers] =~ s/^\[|\]$//g; # remove bookends
                if ($data[$type] eq 'appgroup'){
                        # ACS-INBOUND_PROTOCOLS,appgroup,,[tacacs|tacacs-plus|radius],
                        $$application_groups_ref{$data[$name]} = $data[$name];
                        $$application_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        if ($data[$objmembers] =~ /\|/ ){
                                my @members = split /\|/, $data[$objmembers];
                                foreach (@members){
                                        push @{ $$application_groups_ref{$data[$name]}{'members'}},  $_;
                                }
                        } else {
                                push @{ $$application_groups_ref{$data[$name]}{'members'}},  $data[$objmembers];
                        }
                } elsif ($data[$type] eq 'dyngrp'){
                        # x99MGMT-NSMSS_SERVERS,dyngrp,AUTOMATION USE ONLY ** DO NOT MANUALLY EDIT **,['x99MGMT-NSMSS_TAG'],
                        $$address_groups_ref{$data[$name]} = $data[$name];
                        $$address_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        if ($data[$objmembers] =~ /\|/ ){
                                my @members = split /\|/, $data[$objmembers];
                                foreach (@members){
                                        push @{ $$address_groups_ref{$data[$name]}{'members'}},  $_;
                                }
                        } else {
                                push @{ $$address_groups_ref{$data[$name]}{'members'}},  $data[$objmembers];
                        }
                } elsif ($data[$type] eq 'group'){
                        # GLOBAL-LEGACY_MGMT_ONESOURCE_HOSTS_ITSEC02163,group,DC only  - eg must not match Palo ENT,[unknown-10.200.204.226|unknown-206.197.194.45],
                        $$address_groups_ref{$data[$name]} = $data[$name];
                        $$address_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$address_groups_ref{$data[$name]}{'type'} = "group";
                        if ($data[$objmembers] =~ /\|/ ){
                                my @members = split /\|/, $data[$objmembers];
                                foreach (@members){
                                        push @{ $$address_groups_ref{$data[$name]}{'members'}},  $_;
                                }
                        } else {
                                push @{ $$address_groups_ref{$data[$name]}{'members'}},  $data[$objmembers];
                        }
                } elsif ($data[$type] eq 'host'){
                        # eagp-91corp-e_10.204.78.108m32,host,erfqc.thomsonqc.com,10.204.78.108,,
                        $$addresses_ref{$data[$name]} = $data[$name];
                        $$addresses_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$addresses_ref{$data[$name]}{'type'} = "host";
                        $$addresses_ref{$data[$name]}{'cidr'} = join('/', $data[$ip], "32");
                        $$addresses_ref{$data[$name]}{'ip'} = $data[$ip];
                        $$addresses_ref{$data[$name]}{'netmask'} = $netbits{32};
                        if ($data[$tag]){
                                $$addresses_ref{$data[$name]}{'tag'} = $data[$tag];
                        }
                } elsif ($data[$type] eq 'net'){
                        # ISG_NTC_172.22.136.0m21,net,NTC ISG ENCDOM G_NTCP-00DCMC_172.22.136.0m28,172.22.136.0/21,,
                        # tok-10.106.6.129m32,net,jptokwljdc01,10.106.6.129/32,,
                        $$addresses_ref{$data[$name]} = $data[$name];
                        $$addresses_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$addresses_ref{$data[$name]}{'type'} = "net";
                        $$addresses_ref{$data[$name]}{'cidr'} = $data[$cidr];
                        my $ip = (split /\//, $data[$cidr])[0];
                        my $bits = (split /\//, $data[$cidr])[1];
                        $$addresses_ref{$data[$name]}{'ip'} = $ip;
                        $$addresses_ref{$data[$name]}{'netmask'} = $netbits{$bits};
                        if ($data[$tag]){
                                $$addresses_ref{$data[$name]}{'tag'} = $data[$tag];
                        }
                } elsif ($data[$type] eq 'service'){
                        # TCP-28001,service,tcp,28001,
                        $$services_ref{$data[$name]} = $data[$name];
                        $$services_ref{$data[$name]}{'protocol'} = $data[$protocol];
                        $$services_ref{$data[$name]}{'type'} = $data[$protocol];
                        $$services_ref{$data[$name]}{'port'} = $data[$port];
                } elsif ($data[$type] eq 'srvgroup'){
                        # IMON-OUTBOUND_SERVICES,srvgroup,,[TCP-1248|TCP-5989],
                        $$service_groups_ref{$data[$name]} = $data[$name];
                        $$service_groups_ref{$data[$name]}{'comment'} = $data[$comment];
                        $$service_groups_ref{$data[$name]}{'type'} = "srvgroup";
                        if ($data[$objmembers] =~ /\|/ ){
                                my @members = split /\|/, $data[$objmembers];
                                foreach (@members){
                                        push @{ $$service_groups_ref{$data[$name]}{'members'}},  $_;
                                }
                        } else {
                                push @{ $$service_groups_ref{$data[$name]}{'members'}},  $data[$objmembers];
                        }
                } elsif ($data[$type] eq 'tag'){
                        # x99MGMT-SCOM_TAG,tag,,AUTOMATION USE ONLY ** DO NOT MANUALLY EDIT **
                        my $comment = "3";
                        $$tags_ref{$data[$name]} = $data[$name];
                        $$tags_ref{$data[$name]}{'comment'} = $data[$comment];
                }
        }
        $fh->close();

        # populate tags now
        foreach my $tag (keys %$tags_ref){
                foreach my $address (keys %$addresses_ref){
                        if (exists ($$addresses_ref{$address})){
                                if (exists ($$addresses_ref{$address}{'tag'})){
                                        if ($$addresses_ref{$address}{'tag'} eq $tag){
                                                push @{ $$tags_ref{$tag}{'members'}}, $address;
                                        }
                                }
                        }
                }
        }

}

sub readAppIDs {

        my ( $appids_ref, $appNames_ref ) = @_;

        my $panappidFile = $staticDir."/PAN_application_data.csv";
        my $appID = 0;
        my $appName = 1;
        my $appCategory = 2;
        my $defaultPorts = 3;
        my $dependents = 4;
        my $implied = 5;
        my $fh = new FileHandle;

        $fh->open("<$panappidFile") or die "Cannot open $panappidFile - $!";
        while(<$fh>) {
                chomp($_);
                $_ =~ s/\s+$//;
                my @data = split /\;/, $_;
                $$appNames_ref{$data[$appName]} = $data[$appID];
                $$appids_ref{$data[$appID]}{'id'} = $data[$appID];
                $$appids_ref{$data[$appID]}{'name'} = $data[$appName];
                $$appids_ref{$data[$appID]}{'category'} = $data[$appCategory];
                if (defined $data[$defaultPorts]){
                        if ($data[$defaultPorts] =~ /\,/ ){
                                my @members = split /\,/, $data[$defaultPorts];
                                foreach (@members){
                                        push @{ $$appids_ref{$data[$appID]}{'ports'}}, $_;
                                }
                        } else {
                                push @{ $$appids_ref{$data[$appID]}{'ports'}}, $data[$defaultPorts];
                        }
                }
                if (defined $data[$dependents]){
                        if ($data[$dependents] =~ /\,/ ){
                                my @members = split /\,/, $data[$dependents];
                                foreach (@members){
                                        push @{ $$appids_ref{$data[$appID]}{'dependents'}}, $_;
                                }
                        } elsif ($data[$dependents] ne "") {
                                push @{ $$appids_ref{$data[$appID]}{'dependents'}}, $data[$dependents];
                        }
                }
                if (defined $data[$implied]){
                        if ($data[$implied] =~ /\,/ ){
                                my @members = split /\,/, $data[$implied];
                                foreach (@members){
                                        push @{ $$appids_ref{$data[$appID]}{'implied'}}, $_;
                                }
                        } elsif ($data[$implied] ne "") {
                                push @{ $$appids_ref{$data[$appID]}{'implied'}}, $data[$implied];
                        }
                }
        }
        $fh->close();
}

sub findParentGroups {

        my ( $groups_ref, $parentGroups_ref, $objName, $objType ) = @_;

        foreach my $group (keys %$groups_ref ) {
                foreach my $member (@{$$groups_ref{$group}{'members'}}) {
                        # ensure exact match as some groups as very similar names!
                        if ($member =~ /^$objName$/){
                                push (@$parentGroups_ref, $group);
                        }
                }
        }
}

sub findParentRules {

        my ( $rules_ref, $parentRules_ref, $objName, $objType ) = @_;

        # add for 'srcuser' and 'description'?
        foreach my $rule (keys %$rules_ref) {
                if (($objType eq "tag") or ($objType eq "address") or ($objType eq "addressgrp") or ($objType eq "exclgrp")){
                        if (( grep /$objName/, @{$$rules_ref{$rule}{'srcaddr'}} ) || ( grep /$objName/, @{$$rules_ref{$rule}{'dstaddr'}} )){
                                push (@$parentRules_ref, $rule);
                        }
                } elsif (($objType eq "service") or ($objType eq "servicegrp")){
                        if ( grep /$objName/, @{$$rules_ref{$rule}{'service'}} ){
                                push (@$parentRules_ref, $rule);
                        }
                } elsif (($objType eq "appid") or ($objType eq "appgrp")){
                        if ( grep /$objName/, @{$$rules_ref{$rule}{'application'}} ){
                                push (@$parentRules_ref, $rule);
                        }
                } elsif ($objType eq "NETRE"){
                        if (match_ip($objName, $$rules_ref{$rule}{'ruleNetsre'})){
                                push (@$parentRules_ref, $rule);
                        }
                }
        }
}

sub findObjectFromIP {

        my ( $addresses_ref, $matchedObjects_ref, $ip ) = @_;

        foreach my $addressObject (keys %$addresses_ref){
                if ($$addresses_ref{$addressObject}{'ip'} eq $ip){
                        push (@$matchedObjects_ref, $addressObject);
                }
        }
}

sub printMembersExpanded (\@\%\%\%\%\$\@\%) {

        my $members_ref = shift;
        my $address_groups_ref = shift;
        my $Gaddress_groups_ref = shift;
        my $addresses_ref = shift;
        my $Gaddresses_ref = shift;
        my $ipvf = shift;
        my $nets_ref = shift;
        my $tags_ref = shift;
        my $memberCount = scalar @{$members_ref};
        my $count = 0;

        foreach my $member (@{$members_ref}){
                $member =~ s/^\'|\'$//g; # remove quotes
                # check if member is actually another group
                if (exists($$address_groups_ref{$member})){
                        printMembersExpanded(\@{$$address_groups_ref{$member}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, $ipvf, \@{$nets_ref});
                } elsif (exists($$Gaddress_groups_ref{$member})){
                        printMembersExpanded(\@{$$Gaddress_groups_ref{$member}{'members'}}, \%{$address_groups_ref}, \%{$Gaddress_groups_ref}, \%{$addresses_ref}, \%{$Gaddresses_ref}, $ipvf, \@{$nets_ref});
                # or a tag
                } elsif (exists($$tags_ref{$member})){
                        if ($ipvf == 2){
                                foreach (@{$$tags_ref{$member}{'members'}}){
                                        push @{$nets_ref}, $_;
                                }
                        }
                } else {
                        if ($ipvf){
                                if (exists($$addresses_ref{$member}{'cidr'})){
                                        if ($ipvf == 1){
                                                print "$$addresses_ref{$member}{'cidr'}\n";
                                        } else {
                                                push @{$nets_ref}, $$addresses_ref{$member}{'cidr'};
                                        }
                                } elsif (exists($$Gaddresses_ref{$member}{'cidr'})){
                                        if ($ipvf == 1){
                                                print "$$Gaddresses_ref{$member}{'cidr'}\n";
                                        } else {
                                                push @{$nets_ref}, $$Gaddresses_ref{$member}{'cidr'};
                                        }
                                } elsif (exists($$addresses_ref{$member}{'ip'})){
                                        if ($ipvf == 1){
                                                print "$$addresses_ref{$member}{'ip'}\n";
                                        } else {
                                                push @{$nets_ref}, $$addresses_ref{$member}{'ip'};
                                        }
                                } elsif (exists($$Gaddresses_ref{$member}{'ip'})){
                                        if ($ipvf == 1){
                                                print "$$Gaddresses_ref{$member}{'ip'}\n";
                                        } else {
                                                push @{$nets_ref}, $$Gaddresses_ref{$member}{'ip'};
                                        }
                                }
                        } else {
                                print "$member";
                                $count++;
                                if ($count <= $memberCount) { print ";"; }
                        }
                }
        }
}

sub printMembersPipe {

        my ( $members_ref ) = @_;
        my $memberCount = scalar @{$members_ref};
        my $count = 0;

        foreach (@{$members_ref}){
                print "$_";
                $count++;
                if ($count < $memberCount) { print("|"); }
        }
}

sub printMembers {

        my ( $members_ref ) = @_;
        my $memberCount = scalar @{$members_ref};
        my $count = 0;

        foreach (@{$members_ref}){
                print "$_";
                $count++;
                if ($count < $memberCount) { print(";"); }
        }
}

sub printGroups (\@\$\$) {

        my $groups_ref = shift;
        my $object = shift;
        my $match = shift;
        my @matchedgroups;
        my @nestedgroups;

        foreach my $group (keys %$groups_ref){
                foreach my $member (@{$$groups_ref{$group}{'members'}}) {
                        if ($member eq $object){
                                push @matchedgroups, $group;
                        }
                }
        }

        if ($match){
                foreach my $group (keys %$groups_ref){
                        foreach my $member (@{$$groups_ref{$group}{'members'}}) {
                                foreach my $matchedgroup (@matchedgroups){
                                        if ($member eq $matchedgroup){
                                                push @nestedgroups, $group;
                                        }
                                }
                        }
                }
        }

        if (@matchedgroups){
                print "$object,";
                printMembers(\@matchedgroups);
                if ($match){
                        print ",";
                        printMembers(\@nestedgroups);
                }
                print "\n";
        }
}

sub printCPformat {

        my $address_groups_ref = shift;
        my $addresses_ref = shift;
        my $services_ref = shift;
        my $service_groups_ref = shift;

        # G_OCDS-VA_CP_10.242.128.24_m29,net,10.242.128.24,255.255.255.248,magenta,,,,"OCD PRE PROD VA LAN"
        foreach my $address (sort keys %$addresses_ref ) {
                print "$address,$$addresses_ref{$address}{'type'},$$addresses_ref{$address}{'ip'},$$addresses_ref{$address}{'netmask'},$$addresses_ref{$address}{'colour'},,,,\"$$addresses_ref{$address}{'comment'}\"\n";
        }

        # G_GLOBAL-VA_CP_PPE_NETWORKS,group,G_OCDS-VA_CP_10.242.128.24_m29,,orange,,,,"Global VA Pre Prod CP Scanning Nets"
        # G_GLOBAL-VA_CT_PPE_NETWORKS,group,G_OCDS-VA_CT_10.242.128.88_m29,,orange,,,,"Global VA Pre Prod CT Scanning Nets"
        foreach my $group (sort keys %$address_groups_ref ) {
                foreach my $member (@{$$address_groups_ref{$group}{'members'}}){
                        print "$group,group,$member,,$$address_groups_ref{$group}{'colour'},,,,\"$$address_groups_ref{$group}{'comment'}\"\n"
                }
        }

        # gUserCheck,tcp,18300,default,FireBrick,,,default,"Check Point Daemon Protocol"
        foreach my $service (sort keys %$services_ref ) {
                print "$service,$$services_ref{$service}{'type'},$$services_ref{$service}{'port'},$$services_ref{$service}{'timeout'},$$services_ref{$service}{'colour'},,,,\"$$services_ref{$service}{'comment'}\"\n";
        }

        # gFW1_clntauth,srvgroup,gFW1_clntauth_telnet,,FireBrick,,,,"Check Point VPN-1 & FireWall-1 Client Authentication"
        # gFW1_clntauth,srvgroup,gFW1_clntauth_http,,FireBrick,,,,"Check Point VPN-1 & FireWall-1 Client Authentication"
        foreach my $group (sort keys %$service_groups_ref ) {
                foreach my $member (@{$$service_groups_ref{$group}{'members'}}){
                        print "$group,srvgroup,$member,,$$service_groups_ref{$group}{'colour'},,,,\"$$service_groups_ref{$group}{'comment'}\"\n"
                }
        }
}

sub printObjType {

        my $object_ref = shift;

        my $total = scalar(keys %$object_ref);
        my $count = 0;

        foreach my $object (sort keys %$object_ref) {
                $count++;
                print "$object";
                if ($count < $total){
                        print ",";
                }
        }
        print "\n";
}

sub printPARules (\%\%\%\%\%\%\%\%\%\%\@) {

        my $Gaddress_groups_ref = shift;
        my $Gaddresses_ref = shift;
        my $address_groups_ref = shift;
        my $addresses_ref = shift;
        my $services_ref = shift;
        my $service_groups_ref = shift;
        my $applications_ref = shift;
        my $application_groups_ref = shift;
        my $tags_ref = shift;
        my $rules_ref = shift;
        my $matchedRules_ref = shift;

        # print out the matched rules
        print "Rule Name,Src Zone,Src Address,Src User,Dest Address,Dest Zone,Application,Service,HIP,URL,Ruletype,Logstart,Disabled,Action,Tag,Description\n";
        foreach my $rule (@{$matchedRules_ref}){
                print "$$rules_ref{$rule}{'name'},";
                print "$$rules_ref{$rule}{'srczone'},";
                foreach my $src (@{$$rules_ref{$rule}{'srcaddr'}}) {
                        print "$src";
                        if ($src ne 'any'){
                                print ";";
                                if ($src =~ /^G_/){
                                        printMembers(\@{$$Gaddress_groups_ref{$src}{'members'}});
                                } else {
                                        printMembers(\@{$$address_groups_ref{$src}{'members'}});
                                }
                                foreach my $member (@{$$address_groups_ref{$src}{'members'}}) {
                                        if ($member =~ /_TAG/){
                                                print "|";
                                                $member =~ s/\'//g;
                                                printMembers(\@{$$tags_ref{$member}{'members'}});
                                        }
                                }
                        }
                }
                print ",";
                printMembers(\@{$$rules_ref{$rule}{'srcuser'}});
                print ",";
                foreach my $dst (@{$$rules_ref{$rule}{'dstaddr'}}) {
                        print "$dst";
                        if ($dst ne 'any'){
                                print ";";
                                if ($dst =~ /^G_/){
                                        printMembers(\@{$$Gaddress_groups_ref{$dst}{'members'}});
                                } else {
                                        printMembers(\@{$$address_groups_ref{$dst}{'members'}});
                                }
                                foreach my $member (@{$$address_groups_ref{$dst}{'members'}}) {
                                        if ($member =~ /_TAG/){
                                                print "|";
                                                $member =~ s/\'//g;
                                                printMembers(\@{$$tags_ref{$member}{'members'}});
                                        }
                                }
                        }
                }
                print ",$$rules_ref{$rule}{'dstzone'},";
                foreach my $appid (@{$$rules_ref{$rule}{'application'}}) {
                        print "$appid";
                        if ($appid ne 'any'){
                                print ";";
                        }
                        printMembers(\@{$$application_groups_ref{$appid}{'members'}});
                }
                print ",";
                foreach my $service (@{$$rules_ref{$rule}{'service'}}) {
                        print "$service";
                        if (($service ne 'any') and ($service ne 'application-default')){
                                print ";";
                        }
                        printMembers(\@{$$service_groups_ref{$service}{'members'}});
                }
                print ",$$rules_ref{$rule}{'hip'},";
                print "$$rules_ref{$rule}{'url'},";
                print "$$rules_ref{$rule}{'ruletype'},";
                print "$$rules_ref{$rule}{'logstart'},";
                print "$$rules_ref{$rule}{'disabled'},";
                print "$$rules_ref{$rule}{'action'},";
                print "$$rules_ref{$rule}{'tag'},";
                print "$$rules_ref{$rule}{'description'}\n";
        }
}

sub printCPRules (\%\%\%\%\%\@) {

        my $address_groups_ref = shift;
        my $addresses_ref = shift;
        my $services_ref = shift;
        my $service_groups_ref = shift;
        my $exclGroups_ref = shift;
        my $rules_ref = shift;
        my $matchedRules_ref = shift;
        my $count = 0;

        # print out the matched rules
        print "Rule Name,Src Addr,Dst Addr,VPN,Service,Action,Track,Target,Time,Description,Location\n";
        foreach my $rule (@{$matchedRules_ref}){
                print "$$rules_ref{$rule}{'name'},";
                my $objCount = scalar @{$$rules_ref{$rule}{'srcaddr'}};
                $count = 0;
                foreach my $src (@{$$rules_ref{$rule}{'srcaddr'}}) {
                        print "$src";
                        if (exists($$address_groups_ref{$src})){
                                print ":";
                                printMembers(\@{$$address_groups_ref{$src}{'members'}});
                        }
                        $count++;
                        if ($count < $objCount) { print("|"); }
                }
                print ",";
                my $objCount = scalar @{$$rules_ref{$rule}{'dstaddr'}};
                $count = 0;
                foreach my $dst (@{$$rules_ref{$rule}{'dstaddr'}}) {
                        print "$dst";
                        if (exists($$address_groups_ref{$dst})){
                                print ":";
                                printMembers(\@{$$address_groups_ref{$dst}{'members'}});
                        }
                        $count++;
                        if ($count < $objCount) { print("|"); }
                }
                print ",";
                print "$$rules_ref{$rule}{'vpn'},";
                my $objCount = scalar @{$$rules_ref{$rule}{'service'}};
                $count = 0;
                foreach my $service (@{$$rules_ref{$rule}{'service'}}) {
                        print "$service";
                        if (exists($$service_groups_ref{$service})){
                                print ":";
                                printMembers(\@{$$service_groups_ref{$service}{'members'}});
                        }
                        $count++;
                        if ($count < $objCount) { print("|"); }
                }
                print ",";
                print "$$rules_ref{$rule}{'action'},";
                print "$$rules_ref{$rule}{'track'},";
                printMembersPipe(\@{$$rules_ref{$rule}{'target'}});
                print ",";
                print "$$rules_ref{$rule}{'time'},";
                print "$$rules_ref{$rule}{'description'},";
                print "$$rules_ref{$rule}{'location'}\n";
        }
}

sub usage {

        my $version = shift;
        print "\n$me (v$version) - Query tool for firewall management databases (from archived configuration files)\n\n";
        print "Usage:\n\n";
        print "\tsudo $me.pl --db <firewall database name>\n\n";
        print "\texample databases include:-\n\n";
        print "\t\t\t \'pa_global\' for Palo Alto Global Objects\n";
        print "\t\t\t \'cp_global\' for Check Point Global Objects\n";
        print "\t\t\t \'sma-nscma337\' for Check Point CMA Objects\n";
        print "\t\t\t \'management_modules\' for Palo Alto Device Group Objects\n\n";
        print "Optional:\n\n";
        print "\t--list [types|type|all]        : lists all object types or all object names of \'type\'\n";
        print "\t--obj [name]                   : lists object contents matching [name]\n";
        print "\t--grp [name]                   : lists parent groups for object matching [name]\n";
        print "\t--ip [ip]                      : lists IP, exact matching objects and any groups the IP is a member of (including tags)\n";

        print "\t--ipvf                         : (in combination with --obj) outputs ip/cidr format for address/address-group/exclusion-group-delta contents\n";
        print "\t--regex                        : (in combination with --obj) outputs object names matching pattern\n";
        print "\t--rule <object name/IP>        : lists rules with expanded fields for given object or explicit IP (will find objects hidden in groups)\n";
        print "\t--match                        : (in combination with --rule) if IP provided will find implicit match, e.g. if IP would match /24 object in rule\n";
        print "\t--match                        : (in combination with --ip) will find implicit match in exclusion group delta\n";
        print "\t--match                        : (in combination with --grp) will find all nested groups that object indirectly appears in (e.g. not just parent groups)\n";
        print "\t--itsec                        : (in combination with --rule) lists ITSEC rules and objects for given tag (additional to dynamic objects)\n";
        print "\t--debug                        : (in combination with --rule) debug printing information\n";
        print "\t--dump [cpformat|paformat]     : prints the database, expanded tags and rules. cpformat will print in Check Point format\n";
        print "\t--policy                       : (in combination with --dump) prints expanded rules only\n";
        print "\t--global                       : (in combination with --policy) prints global/device group rules as well\n\n";

        print "Examples:\n\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --list types\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj SPLUNK-INBOUND_PROTOCOLS\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj SPLUNK-INBOUND_SERVICES\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj x99MGMT-SPLUNK_SERVERS\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj x99MGMT-SPLUNK_TAG\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj plnp-91ecom-a_10.185.12.93m32\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj GLOBAL-LEGACY_MGMT_SPLUNK_HOSTS_ITSEC02163 --ipvf\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --obj BIGDATA --regex\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --grp G_TCP-8888\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --grp webdav\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --grp ent_10.5.78.60m32\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db cp_global --grp G_PLNP-93BETA-WMBI1-A_10.179.254.136m29 --match\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --ip 10.231.113.7\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --ip 159.42.34.32\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --ip 10.5.78.60\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db sma-nscma413 --ip 10.222.251.208 --match\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule dtls\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule G_TCP-1521\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule plnp-91ecom-a_10.185.12.92m32\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule 10.5.78.60 --match\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule x99MGMT-HPSIM_TAG\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule x99MGMT-HPSIM_TAG --itsec\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db management_modules --rule x99MGMT-HPSIM_TAG --itsec --debug\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db pa_global --grp G_PLNP-90ECOM-SHRS1-A_159.43.12.128m25\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db pa_global --dump cpformat\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db clear_qa --dump paformat --policy\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db lon-mgt-pa-fwa1-vsys1 --dump paformat --policy --global\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db cp_global --obj gntp\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db cp_global --obj G_HKGS-93CORP-TDNM1-A_PEER_NETWORKS\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db sma-nscma001 --ip 192.168.82.5\n";
        print "\tsudo RTRL_FWDBQueryTool.pl --db lonp-inge-pa-fwa1-vsys1 --obj GLOBAL-CORP_MGMT_NETWORKS\n";

}

########################################################################################
#
# Script END
#
########################################################################################

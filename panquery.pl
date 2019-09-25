#!/usr/bin/perl
#
my $version = "1.0";
# Date          04 July, 2017
# Purpose       Palo Alto Firewall Query Tool to report on rule and object usage using offline configs
# Revision      24 September, 2019
#
# 1.0 - released version

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

my $database;
my $debug;
my $depth;
my $dump;
my $duplicates;
my $grp;
my $help;
my $ip;
my $ipvf;
my $match;
my $me = basename($0, ".pl");
my $obj;
my $objFile;
my $policy;
my $regex;
my $rule;
my $shared;
my $unused;
my $used;
my $baseDir = "/root/Documents";
my $scriptDir = $baseDir."/Scripts";
my $inputDir = $scriptDir."/unused-rules";
my $staticDir = $scriptDir."/common_data/DeviceGroups";

my $fh = new FileHandle;
my $ofh = new FileHandle;
my $goFile = "PA-objects.csv";
my $appidfile = "PAN_application_8187-5632.csv";
my @lists;
my @networks;
my @parentGroups;
my @parentRules;
my %addresses = ();
my %address_groups = ();
my %applications = ();
my %application_groups = ();
my %application_filters = ();
my %predefined_applications = ();
my %services = ();
my %service_groups = ();
my %tags = ();
my %dips = ();
my %zones = ();
my %routes = ();
my %Gaddresses = ();
my %Gaddress_groups = ();
my %Gapplication_groups = ();
my %Gservices = ();
my %Gservice_groups = ();
my %Gtags = ();
my %rules = ();
tie %rules, 'Tie::IxHash';
my %nats = ();
tie %nats, 'Tie::IxHash';
my %capabilities = ();
my %appids = ();
my %used_addresses = ();
my %used_applications = ();
my %used_services = ();
my %used_tags = ();

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
        "debug" => \$debug,
        "depth:s" => \$depth,
        "dump:s" => \$dump,
        "duplicates" => \$duplicates,
        "grp:s" => \$grp,
        "ip:s" => \$ip,
        "ipvf" => \$ipvf,
        "list:s" => \@lists,
        "match" => \$match,
        "obj:s" => \$obj,
        "policy" => \$policy,
        "regex" => \$regex,
        "rule:s" => \$rule,
        "shared" => \$shared,
        "unused" => \$unused,
        "used" => \$used,
        "help" => \$help
);

usage($version) and exit if ($help);
usage($version) and print "ERROR01 : db must not be empty\n" and exit if (!$database);
usage($version) and print "ERROR02 : one of list, obj, grp, ip, rule, unused, used or dump required\n" and exit if ((!@lists) and (!$obj) and (!$grp) and (!$ip) and (!$rule) and (!$unused) and (!$used) and (!$dump));

########################################################################################
#
# Read in offline object files created by panmanager
#
########################################################################################

# can have four types of file - shared-panorama, device group, shared-fw, vsysX
# read Panorama shared
#read_panmanager_format(\%Gapplication_groups, \%Gaddress_groups, \%Gaddresses, \%Gservices, \%Gservice_groups, \%Gtags, $goFile, $inputDir);
#read_panmanager_format(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $vsysobjFile, $inputDir);
#read_panmanager_format(\%application_groups, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, $sharedobjFile, $inputDir);

# read provided file
read_panmanager_format(\%applications, \%application_groups, \%application_filters, \%address_groups, \%addresses, \%services, \%service_groups, \%tags, \%zones, \%routes, \%dips, \%rules, \%nats, $database, $inputDir);

readAppIDs(\%appids, \%predefined_applications, $appidfile, $staticDir);

########################################################################################
#
# cli switches : --unused
#
########################################################################################

if (($unused) or ($used)){

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

		next if ($href->{objtype} !~ /security-rule/);
		$location = $href->{location};

       	 	my $src = $href->{source};
        	$src =~ s/[\[\]']+//g;

        	my $dst = $href->{destination};
        	$dst =~ s/[\[\]']+//g;

        	my $app = $href->{application};
        	$app =~ s/[\[\]']+//g;

        	my $svc = $href->{service};
        	$svc =~ s/[\[\]']+//g;

        	my $tag = $href->{tag};
        	$tag =~ s/[\[\]']+//g;

        	if (($src) and ($src ne "any")){
                	if ($src =~ /\,/){
                        	my @data = split (/\,/, $src);
				s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
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
				s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
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
				s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
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
				s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
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
				s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
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

	# figure out the applications/application filters used in application groups
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

	my $outputfile = join('.', "panquery", $location, "delete.csv");
        $ofh->open(">$outputfile") or die "Cannot open $outputfile - $!";

	# address and address groups cannot share same name
	my %all_addresses = (%address_groups, %addresses);
	foreach my $object (sort keys %all_addresses){
        	if (!exists($used_addresses{$object})){
			if ($unused){
                		print "addresses object unused \'$object\'\n";
				if (exists($addresses{$object})){
					$ofh->print("palo,address,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} elsif (exists($address_groups{$object})){
					$ofh->print("palo,address-group,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} else {
                			$ofh->print("#ERROR src/dst field object missing from $database (shared object?) \'$object\'\n");
				}
			}
        	} else {
			if ($used){
                		print "addresses object used \'$object\'\n";
			}
        	}
	}

	# applications, application groups and application filters cannot share same name
	my %all_applications = (%applications, %application_groups, %application_filters);
	foreach my $object (sort keys %all_applications){
        	if (!exists($used_applications{$object})){
			if ($unused){
                		print "applications object unused \'$object\'\n";
				if (exists($applications{$object})){
					$ofh->print("palo,application,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} elsif (exists($application_groups{$object})){
					$ofh->print("palo,application-group,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} elsif (exists($application_filters{$object})){
					$ofh->print("palo,application-filter,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} else {
                			$ofh->print("#ERROR application field object missing from $database (shared object?) \'$object\'\n");
				}
			}
        	} else {
			if ($used){
                		print "applications object used \'$object\'\n";
			}
		}
	}

	my $found = "TRUE";
	# service and service groups CAN share same name
	foreach my $object (sort keys %services){
		if (!exists($used_services{$object})){
			undef $found;
                } else {
			if ($used){
                        	print "services object used \'$object\'\n";
			}
		}
	}

        foreach my $object (sort keys %service_groups){
        	if (!exists($used_services{$object})){
			if (!$found){
				if ($unused){
                        		print "services object unused \'$object\'\n";
					if (exists($services{$object})){
						$ofh->print("palo,service,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
					}
					if (exists($service_groups{$object})){
						$ofh->print("palo,service-group,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
					}
					if ((!exists($services{$object})) and (!exists($service_groups{$object}))){
                				$ofh->print("#ERROR service field object missing from $database (shared object?) \'$object\'\n");
					}
				}
			}
                } else {
			if ($used){
                        	print "services object used \'$object\'\n";
			}
        	}
	}

	foreach my $object (sort keys %tags){
        	if (!exists($used_tags{$object})){
			if ($unused){
                		print "tag object unused \'$object\'\n";
				if (exists($tags{$object})){	
					$ofh->print("palo,tag,delete,\"$location\",\"$object\",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,end\n");
				} else {
					$ofh->print("#ERROR tag field object missing from $database (shared object?) \'$object\'\n");
				}
                        }
        	} else {
			if ($used){
                		print "tag object used \'$object\'\n";
			}
		}
	}
	$ofh->close();

	#######################################################################################
	#
	# Check for items in the policy that are not in the provided file
	#
	#######################################################################################

	foreach my $object (sort keys %used_addresses){
        	if (!exists($all_addresses{$object})){
                	print "ERROR src/dst field object missing from $database \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %used_applications){
        	if (!exists($all_applications{$object})){
        		if (!exists($predefined_applications{$object})){
               	 		print "ERROR application field object missing from $database \'$object\'\n";
			}
        	}
	}

	foreach my $object (sort keys %used_services){
        	if ((!exists($services{$object})) and (!exists($service_groups{$object}))){
                	print "ERROR service field object missing from $database \'$object\'\n";
        	}
	}

	foreach my $object (sort keys %used_tags){
        	if (!exists($tags{$object})){
                	print "ERROR tag field object missing from $database \'$object\'\n";
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
                print "addr,addrgrp,app,appftr,appgrp,dip,route,svc,svcgrp,tag,zone,all\n";
        } elsif ($list eq "addr"){
                printObjType(\%addresses);
        } elsif ($list eq "addrgrp"){
                printObjType(\%address_groups);
        } elsif ($list eq "app"){
                printObjType(\%applications);
        } elsif ($list eq "appgrp"){
                printObjType(\%application_groups);
        } elsif ($list eq "appftr"){
                printObjType(\%application_filters);
        } elsif ($list eq "svc"){
                printObjType(\%services);
        } elsif ($list eq "svcgrp"){
                printObjType(\%service_groups);
        } elsif ($list eq "tag"){
                printObjType(\%tags);
        } elsif ($list eq "dip"){
                printObjType(\%dips);
        } elsif ($list eq "zone"){
                printObjType(\%zones);
        } elsif ($list eq "route"){
                printObjType(\%routes);
        } elsif ($list eq "all"){
                printObjType(\%addresses);
                printObjType(\%address_groups);
                printObjType(\%services);
                printObjType(\%service_groups);
                printObjType(\%applications);
                printObjType(\%application_groups);
                printObjType(\%application_filters);
                printObjType(\%tags);
                printObjType(\%dips);
                printObjType(\%zones);
                printObjType(\%routes);
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

        if (exists($zones{$obj})){
                print "$obj,$zones{$obj}{'name'}\n";
        }

        if (exists($applications{$obj})){
                print "$obj,$applications{$obj}{'description'},$applications{$obj}{'tag'}";
                print "\n";
        }

        if (exists($application_filters{$obj})){
                print "$obj,$application_filters{$obj}{'category'},$application_filters{$obj}{'tag'}";
                print "\n";
        }

        if (exists($application_groups{$obj})){
                print "$obj,";
                printMembers(\@{$application_groups{$obj}{'members'}});
                print "$application_groups{$obj}{'tag'}\n";
        }

        if (exists($static_routes{$obj})){
                print "$obj,$static_routes{$obj}{'destination'},$static_routes{$obj}{'nexthop'}";
                print "\n";
        }

        if (exists($tags{$obj})){
                print "$obj,$tags{$obj}{'description'},";
                printMembers(\@{$tags{$obj}{'members'}});
                print "\n";
        }

        if (exists($addresses{$obj})){
                if (defined $ipvf){
                        print "$addresses{$obj}{'cidr'}\n";
                } else {
                        print "$obj,$addresses{$obj}{'cidr'},$addresses{$obj}{'ip'},$addresses{$obj}{'netmask'},$addresses{$obj}{'type'},$addresses{$obj}{'description'},$addresses{$obj}{'tag'},$addresses{$obj}{'value'}\n";
                }
        }

        if (exists($services{$obj})){
                print "$obj,$services{$obj}{'protocol'},$services{$obj}{'sport'},$services{$obj}{'dport'},$services{$obj}{'description'},$services{$obj}{'tag'}\n";
        }

        if (exists($address_groups{$obj})){
		if ($address_groups{$obj}{'subtype'} eq 'static'){
                	if (defined $ipvf){
                        	printMembersExpanded(\@{$address_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                	} elsif (defined $depth){
                        	printMembers(\@{$address_groups{$obj}{'members'}});
                	} else {
                        	print "$obj,$address_groups{$obj}{'description'},$address_groups{$obj}{'subtype'},";
                        	printMembersExpanded(\@{$address_groups{$obj}{'members'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
                        	print "\n";
                	}
		} else {
                        print "$obj,$address_groups{$obj}{'description'},$address_groups{$obj}{'subtype'},";
                        printMembersExpanded(\@{$address_groups{$obj}{'tags'}}, \%address_groups, \%Gaddress_groups, \%addresses, \%Gaddresses, $ipvf);
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
                print "$service_groups{$obj}{'tag'}\n";
        }

        if ($regex){
                foreach (keys %dips){
                        if ($_ =~ m/$obj/){
                                print "dip,$_\n";
                        }
                }
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
                foreach (keys %application_filters){
                        if ($_ =~ m/$obj/){
                                print "appfilter,$_\n";
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
        } elsif ((exists($application_groups{$grp})) or (exists($appids{$grp})) or (exists($applications{$grp})) or (exists($application_filters{$grp}))){
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
			foreach my $address (sort keys %addresses){
				if (exists ($addresses{$address}{'netre'})){
                        		if (match_ip($ip, $addresses{$address}{'netre'})){
						print "$address,$addresses{$address}{'cidr'}\n";
					}
				}
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
# cli switches : --dump --debug --policy
#
########################################################################################

if (($dump) and ($policy)){
        foreach my $rule (keys %rules) {
                push (@parentRules, $rule);
        }
        printPARules(\%Gaddress_groups, \%Gaddresses, \%address_groups, \%addresses, \%services, \%service_groups, \%applications, \%application_groups, \%tags, \%rules, \@parentRules);
        undef @parentRules;
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
# cli switches : --rule
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
        } elsif (exists ($applications{$rule})){
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

        foreach my $parentGroup (@parentGroups){
                findParentRules(\%rules, \@parentRules, $parentGroup, $objType);
        }

        my @unique_parentRules = do { my %seen; grep { !$seen{$_}++ } @parentRules };

        printPARules(\%Gaddress_groups, \%Gaddresses, \%address_groups, \%addresses, \%services, \%service_groups, \%applications, \%application_groups, \%tags, \%rules, \@unique_parentRules);
        exit;
}

########################################################################################
#
# subroutines
#
########################################################################################

sub make_array_from_str {

	#take Python list in string format and return an array
    	# e.g. ['nat-rule', 'pre-nat-rule', 'post-nat-rule']
	# ['vlan0410-Desktop-Engg-Dev', 'vlan0454-UNSWIT-Users']

    	my $python_list_string = shift;
    	my @data;

    	if ($python_list_string){
    		$python_list_string =~ s/[\[\]']+//g; # remove bookends and single quotes
        	if ($python_list_string =~ /\,/){
        		@data = split (/\,/, $python_list_string);
			s{^\s+|\s+$}{}g foreach @data; # remove all leading/trailing whitespace from each array element
        	} else {
            		push @data, $python_list_string;
        	}
    	}

    	return @data;
}

sub read_panmanager_format {

    # have to do the objects first and then the rules as cannot figure out nested groups otherwise

    my ( $applications_ref, $application_groups_ref, $application_filters_ref, $address_groups_ref, $addresses_ref, $services_ref, $service_groups_ref, $tags_ref, $zones_ref, $static_routes_ref, $dips_ref, $rules_ref, $nats_ref, $objFile, $dir ) = @_;

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
        	my @members = make_array_from_str($row->[$members]);
        	my @tags = make_array_from_str($row->[$tag]);
        	my @values = make_array_from_str($row->[$value]);
        	if ($row->[$location] =~ /__/){
            		$row->[$location] = (split /__/, $row->[$location])[0];
        	}
        	#if ($href->{objtype} eq "address"){
        	if ($row->[$type] eq 'address'){
            		$$addresses_ref{$row->[$name]} = $row->[$name];
            		$$addresses_ref{$row->[$name]}{'description'} = $row->[$description];
            		$$addresses_ref{$row->[$name]}{'type'} = $row->[$subtype];
			foreach my $tag (@tags){
            			push @{ $$addresses_ref{$row->[$name]}{'tag'}}, $tag;
			}
            		if ($row->[$subtype] eq 'ip-netmask'){
                		if ($row->[$cidr] =~ /\//){
                    			my $ip = (split /\//, $row->[$cidr])[0];
                    			my $bits = (split /\//, $row->[$cidr])[1];
                    			$$addresses_ref{$row->[$name]}{'ip'} = $ip;
                    			$$addresses_ref{$row->[$name]}{'netmask'} = $netbits{$bits};
                			$$addresses_ref{$row->[$name]}{'cidr'} = $row->[$cidr];
                		} else {
					# we must be host address
                    			$$addresses_ref{$row->[$name]}{'ip'} = $row->[$cidr];
                    			$$addresses_ref{$row->[$name]}{'netmask'} = $netbits{'32'};
					my $net = join ('/', $row->[$cidr], '32'); 
                			$$addresses_ref{$row->[$name]}{'cidr'} = $net;
				}
				if (($$addresses_ref{$row->[$name]}{'cidr'} !~ /32$/) and ($$addresses_ref{$row->[$name]}{'cidr'} !~ /:/)){
					push my @net, $$addresses_ref{$row->[$name]}{'cidr'};
                    			$$addresses_ref{$row->[$name]}{'netre'} = create_iprange_regexp_depthfirst(@net);
				}
            		} else {
				foreach my $value (@values){
                			push @{ $$addresses_ref{$row->[$name]}{'value'}}, $value;
				}
                		# could run nslookup here on fqdn objects?
            		}
        	} elsif ($row->[$type] eq 'address-group'){
            		$$address_groups_ref{$row->[$name]}{'name'} = $row->[$name];
            		$$address_groups_ref{$row->[$name]}{'description'} = $row->[$description];
            		$$address_groups_ref{$row->[$name]}{'subtype'} = $row->[$subtype];
            		if ($row->[$subtype] eq 'dynamic'){
				foreach my $value (@values){
                			push @{ $$addresses_ref{$row->[$name]}{'tags'}}, $value;
				}
            		} elsif ($row->[$subtype] eq 'static'){
                		if (!$row->[$members]){
                    			push @{ $$address_groups_ref{$row->[$name]}{'members'}}, 'placeholder';
                		} else {
					foreach my $member (@members){
                    				push @{ $$address_groups_ref{$row->[$name]}{'members'}}, $member;
					}
                		}
            		}
        	} elsif ($row->[$type] eq 'service'){
            		$$services_ref{$row->[$name]}{'name'} = $row->[$name];
            		$$services_ref{$row->[$name]}{'protocol'} = $row->[$protocol];
            		$$services_ref{$row->[$name]}{'sport'} = $row->[$source_port];
            		$$services_ref{$row->[$name]}{'dport'} = $row->[$destination_port];
            		$$services_ref{$row->[$name]}{'description'} = $row->[$description];
			foreach my $tag (@tags){
            			push @{ $$service_ref{$row->[$name]}{'tag'}}, $tag;
			}
        	} elsif ($row->[$type] eq 'service-group'){
            		$$service_groups_ref{$row->[$name]}{'name'} = $row->[$name];
			foreach my $member (@members){
            			push @{ $$service_groups_ref{$row->[$name]}{'members'}}, $member;
			}
			foreach my $tag (@tags){
            			push @{ $$service_groups_ref{$row->[$name]}{'tag'}}, $tag;
			}
        	} elsif ($row->[$type] eq 'tag'){
            		$$tags_ref{$row->[$name]}{'name'} = $row->[$name];
            		$$tags_ref{$row->[$name]}{'description'} = $row->[$description];
        	} elsif ($row->[$type] eq 'dip'){
        		foreach my $member (@members){
                		$$dips_ref{$row->[$name]}{'name'} = join('__', $member, $row->[$tag]);
                		$$dips_ref{$row->[$name]}{'ip'} = $member;
				foreach my $tag (@tags){
            				push @{ $$dips_ref{$row->[$name]}{'tag'}}, $tag;
				}
            		}
        	} elsif ($row->[$type] eq 'route'){
            		$$static_routes_ref{$row->[$name]}{'name'} = $row->[$name];
            		$$static_routes_ref{$row->[$name]}{'destination'} = $row->[$cidr];
            		$$static_routes_ref{$row->[$name]}{'nexthop_type'} = $row->[$subtype];
            		$$static_routes_ref{$row->[$name]}{'nexthop'} = $row->[$nexthop];
            		$$static_routes_ref{$row->[$name]}{'interface'} = $row->[$interface];
            		$$static_routes_ref{$row->[$name]}{'admin_dist'} = $row->[$admin_dist];
            		$$static_routes_ref{$row->[$name]}{'metric'} = $row->[$metric];
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
            		$$application_groups_ref{$row->[$name]} = $row->[$name];
			foreach my $member (@members){
            			push @{ $$application_groups_ref{$row->[$name]}{'members'}}, $member;
			}
			foreach my $tag (@tags){
            			push @{ $$application_groups_ref{$row->[$name]}{'tag'}}, $tag;
			}
        	} elsif ($row->[$type] eq 'application-filter'){
            $$application_filters_ref{$row->[$name]} = $row->[$name];
			foreach my $tag (@tags){
            			push @{ $$application_filters_ref{$row->[$name]}{'tag'}}, $tag;
			}
            $$application_filters_ref{$row->[$name]}{'category'} = $row->[$category];
            $$application_filters_ref{$row->[$name]}{'subcategory'} = $row->[$subcategory];
            $$application_filters_ref{$row->[$name]}{'technology'} = $row->[$technology];
            $$application_filters_ref{$row->[$name]}{'risk'} = $row->[$risk];
            $$application_filters_ref{$row->[$name]}{'evasive'} = $row->[$evasive];
            $$application_filters_ref{$row->[$name]}{'excessive_bandwidth_use'} = $row->[$excessive_bandwidth_use];
            $$application_filters_ref{$row->[$name]}{'prone_to_misuse'} = $row->[$prone_to_misuse];
            $$application_filters_ref{$row->[$name]}{'is_saas'} = $row->[$is_saas];
            $$application_filters_ref{$row->[$name]}{'transfers_files'} = $row->[$transfers_files];
            $$application_filters_ref{$row->[$name]}{'tunnels_other_apps'} = $row->[$tunnels_other_apps];
            $$application_filters_ref{$row->[$name]}{'used_by_malware'} = $row->[$used_by_malware];
            $$application_filters_ref{$row->[$name]}{'has_known_vulnerabilities'} = $row->[$has_known_vulnerabilities];
            $$application_filters_ref{$row->[$name]}{'pervasive'} = $row->[$pervasive];
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

sub findtaguse {

	# where can tags be used?
        my ( $tags_ref, $addresses_ref ) = @_;

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

        my ( $appids_ref, $applications_ref, $appfile, $dir  ) = @_;

        my $appID = 0;
        my $appName = 1;
        my $appCategory = 2;
        my $defaultPorts = 3;
        my $dependents = 4;
        my $implied = 5;
        my $fh = new FileHandle;

        $fh->open("<$dir/$appfile") or die "Cannot open $appfile - $!";
        while(<$fh>) {
                chomp($_);
                $_ =~ s/\s+$//;
                my @data = split /\;/, $_;
                $$applications_ref{$data[$appName]} = $data[$appID];
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

sub printObjType {

        my $object_ref = shift;

        my $total = scalar(keys %$object_ref);
        my $count = 0;

	if ($total > 0){
        	foreach my $object (sort keys %$object_ref) {
                	$count++;
                	print "$object";
                	if ($count < $total){
                        	print ",";
                	}
        	}
        	print "\n";
	}
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
                printMembers(\@{$$rules_ref{$rule}{'source_user'}});
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
                print "$$rules_ref{$rule}{'log_start'},";
                print "$$rules_ref{$rule}{'disabled'},";
                print "$$rules_ref{$rule}{'action'},";
                print "$$rules_ref{$rule}{'tag'},";
                print "$$rules_ref{$rule}{'description'}\n";
        }
}

sub usage {

        my $version = shift;
        print "\n$me (v$version) - Query tool for firewall databases created with panmanager\n\n";
        print "Usage:\n\n";
        print "\tsudo $me.pl --db <firewall database name> <options>\n\n";
        print "Options:\n\n";
        print "\t--list {types|type|all} 			: lists available object types, all object names of \'type x\' or all objects\n";
        print "\t--obj <name> [{--ipvf|--regex}]			: lists object contents exactly matching <name>\n";
        print "							: --ipvf outputs ip/cidr format for address/address-group objects\n";
        print "							: --regexp outputs object names matching pattern\n";
        print "\t--grp <name> [--match]				: lists parent groups for object matching <name>\n";
        print "			 				: --match will find all nested groups that object indirectly appears in (e.g. not just parent groups)\n";
        print "\t--ip <ip> [--match]				: lists IP and explicit matching objects. Also lists any address groups/tags the matched object is a member of\n";
        print "							: --match will find implicit match in address groups and print containing cidr (e.g. within netmask)\n";
        print "\t--rule {object name|ip} [{--match|--debug}]	: lists rules with expanded fields for given object or explicit IP (will find objects hidden in groups)\n";
        print "							: --match if IP provided will find implicit match, e.g. if IP would match /24 object in rule\n";
        print "							: --debug debug printing information\n";
        print "\t--dump {csv|json} [--policy] [--shared]		: prints the database, expanded tags and rules\n";
        print "							: --policy prints expanded rules only\n";
        print "							: --shared prints shared/device group rules as well\n\n";

        print "Examples:\n\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --list types\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --list addr\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --list all\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <address>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <address group>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <address group> --ipvf\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <application group>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <service group>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <address group>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <tag>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --obj <pattern> --regex\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --grp <address>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --grp <address> --match\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --grp <application>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --grp <service>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --ip 8.8.8.8\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --ip 8.8.8.8 --match\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule <address>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule <application>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule <service>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule <tag>\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule <tag> --debug\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule 8.8.8.8\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --rule 8.8.8.8 --match\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --dump csv\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --dump csv --policy\n";
        print "\tsudo panquery.pl --db panmanager-output-file.csv --dump json\n";

}

########################################################################################
#
# Script END
#
########################################################################################
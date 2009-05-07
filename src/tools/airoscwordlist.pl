#!/usr/bin/perl

use strict;use warnings;use Getopt::Long;use YAML::Syck qw(LoadFile);

GetOptions("mac-address|m:s"=>\(my $mac),"ssid|s:s"=>\(my $essid),
"filename|f:s" => \(my $filename),"company|c:s" => \(my $company),
"companyfile|cf:s" => \(my $cf),"verbose" => \(my $verbose),
"version|V" => \(my $getversion),"license|L" =>\(my $license));

my $executable;

	# Main Info here.
my $usage="$0 [OPTIONS]\nOPTIONS:\n\t--mac-address|-m\n\t".
"[--essid|-e] \n\t[--filename|-f]\n\t[--company|-c]\n\t--companyfile|-cf\n\t".
"[--verbose|-v]\n\t[--license|-L]\n\t[--version|-V]\n";my $version="1.0";

my $licensewarn="Copyright (C) 2009 David Francos Cuartero
\tThis program is free software; you can redistribute it and/or
\tmodify it under the terms of the GNU General Public License
\tas published by the Free Software Foundation; either version 2
\tof the License, or (at your option) any later version.";
	my $extendedlw="\n\n\tThis program is distributed in the hope that it will be useful,
\tbut WITHOUT ANY WARRANTY; without even the implied warranty of
\tMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
\tGNU General Public License for more details.
\n\tYou should have received a copy of the GNU General Public License
\talong with this program; if not, write to the Free Software
\tFoundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.";

die "Airoscwordlist ".$version."\n".$licensewarn if $getversion;
die $licensewarn.$extendedlw if $license;
die $usage if !$mac or !$cf;

my $comp=LoadFile($cf) or die "ERROR, could not open company file: $!";

sub _guess_company(){
	my $c_mac;for(keys %$comp){$c_mac=$_ if $mac=~/$_/;}
	if ($comp->{$c_mac}){
		return $comp->{$c_mac}{'name'},$comp->{$c_mac}{'exec'};
	} else { exit(404); }
}

sub _execute_wholething(){my $_=shift;
	s/FILENAME/$filename/ if $filename;
	s/MACADDR/$mac/ if $mac;
	s/ESSID/$essid/ if $essid;
	print;
	system($_);
}


$filename=$ENV{'HOME'}."/generated-wordlist-".localtime(time) if !$filename;
$cf="/usr/share/airoscript/default_company_names" if !$cf;

($company,$executable)=&_guess_company($mac) if !$company;
print "Company recognised: $company, executable $executable" if $verbose;

&_execute_wholething($executable);

__DATA__
=head1 NAME
  Airoscwordlist - Automatic wordlist generator for airoscript.


=head1 OPTIONS

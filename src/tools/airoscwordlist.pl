#!/usr/bin/perl
#==============================================================================
#
#         FILE:  airoscwordlist.pl
#
#        USAGE:  ./airoscwordlist.pl  
#
#  DESCRIPTION:  Creates a wordlist automagically according to a config file.
#
#      OPTIONS:  --mac-address|-m
#                --essid|-e 
#                --filename|-f
#                --company|-c
#                --companyfile|-cf
#                --verbose|-v
#                --version|-V
#
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  GPL2+
#       AUTHOR:  David Francos Cuartero (XayOn), yo.orco@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  22/04/09 19:28:24
#     REVISION:  ---
#==============================================================================
use strict;use warnings;use Getopt::Long;use YAML::Syck qw(LoadFile);
GetOptions("mac-address|m:s"=>\(my $mac),"ssid|s:s"=>\(my $essid),
"filename|f:s" => \(my $filename),"company|c:s" => \(my $company),
"companyfile|cf:s" => \(my $cf),"verbose" => \(my $verbose));

my $executable;my $usage="$0 [OPTIONS]\nOPTIONS:\n\t--mac-address|-m\n\t".
"[--essid|-e] \n\t[--filename|-f]\n\t[--company|-c]\n\t--companyfile|-cf\n\t".
"[--verbose|-v]\n\t[--version|-V]\n";
die $usage if !$mac or !$cf;
my $comp=LoadFile($cf) or die "ERROR, could not open company file: $!";

sub _guess_company(){
	my $c_mac;for(keys %$comp){$c_mac=$_ if $mac=~/$_/;}
	if ($comp->{$c_mac}){
		return $comp->{$c_mac}{'name'},$comp->{$c_mac}{'exec'};
	} else { exit(404); }
}

sub _execute_wholething(){
	s/FILENAME/$filename/;
	s/MACADDR/$mac/;
	s/ESSID/$essid/;
	print;
	system($_);
}


$filename=$ENV{'home'}."/generated-wordlist-".localtime(time) if !$filename;
$cf="/usr/share/airoscript/default_company_names" if !$cf;

($executable,$company)=&_guess_company($mac) if !$company;
print "Company recognised: $company" if $verbose;

&_execute_wholething($executable);


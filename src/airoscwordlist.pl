#!/usr/bin/perl 
#===============================================================================
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
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  GPL2+
#       AUTHOR:  David Francos Cuartero (XayOn), yo.orco@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  22/04/09 19:28:24
#     REVISION:  ---
#===============================================================================

use strict;use warnings;use Getopt::Long;use YAML::Syck qw(LoadFile);
my ($mac,$filename,$company,$cf,$verbose,$essid);
GetOptions("mac-address|m:s"=>\$mac,"ssid|s:s"=>\$essid,"filename|f:s" => \$filename,"company|c:s" => \$company,"companyfile|cf:s" => \$cf,"verbose" => $verbose);

sub _guess_company(){for(keys %$conf){$company_mac=$_ if $mac=~/$_/;}if ($comp{$company_mac}){return $comp{$company_mac}{'name'},$comp{$company_mac}{'exec'};}else{exit(404);}}
sub _execute_wholething(){s/FILENAME/$filename/;s/MACADDR/$mac/;s/ESSID/$essid/;print;system($_);}

die $usage if !$mac;
$filename=$ENV{'home'}."/generated-wordlist-".localtime(time) if !$filename;
$cf="/usr/share/airoscript/default_company_names" if !$cf;
$comp=LoadFile($cf);
my ($executable,$company)=_guess_company($mac) if !$company;
print "Company recognised: $company" if $verbose;
_execute_wholething;


#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  airosperl.pl
#
#        USAGE:  airosperl  
#
#  DESCRIPTION:  Airoscript perl gui with glade interface
#
#      OPTIONS:  None
# REQUIREMENTS:  airosperl.pm airosperl.glade
#         BUGS:  As not released, bugs are still on comments. Look for FIXME and TODO
#        NOTES:  
#       AUTHOR:  David Francos Cuartero (XayOn), yo.orco@gmail.com
#      COMPANY:  None
#      VERSION:  0.0
#      CREATED:  01/03/09 19:38:55
#     REVISION:  0
#===============================================================================

use strict;
use warnings;no warnings 'uninitialized';
use Gtk2 -init; # Gtk2
use Gtk2::GladeXML; # Obvious, a parser for glade files
use Gtk2::SimpleList; # Wifi list...
use File::Path;use File::Copy; # This is for copy, delete and move files.
use Cwd 'abs_path';# This is for restarting app
my ($WIFI,$Host_MAC); # Those are being used to all script
if (!-e $ENV{'HOME'}.".airosperl.conf"){require ("/etc/airosperl.conf");}
else{require ($ENV{'HOME'}.".airosperl.conf");}
our ($FT,$FAKE_MAC,$INJMAC,$INJECTRATE); # Those comes from airosperl.conf
#TODO it have to launch a fake auth attack... ideally we could launch a warning with popup_error...
# FIXME client selection menu should be created.
# FIXME Also, wifi data are not really saved...

# Define variables
	my ($bssid,$airservng_addr,$wifi,$DefaultAirservNg,$reso,$capfile,$final,$TreeVie,$TreeView,$action,$os,$mwcmd,$Client_MAC,$FRAG_CLIENT_IP,$FRAG_HOST_IP,$Host_CHAN);# Standard
	my ($ErrLabel,$Airserv_INPUT,$DefaultInput,$Wifi_INPUT,$Reso_INPUT,$MonitorMode,$TreeViewWidget,$Wifi_Interface,$model);# Widgets
	our ($MainWindow, $FileChooserWindow, $SWifiWindow,$ErrWindow,$ChangeMacWindow,$MdkWindow,$WessideWindow,$FolderChooserWindow,$AboutWindow); # Windows
	our (%bin,%termopts,$q);

if (-e "/bin/uname"){$os="Linux";}
else { if (-e $ENV{'systemroot'}){$os="Windows"}}

# Create dump_path before setting actions...
	my $dump_path=&create_dump_path();

my @wepactions=(
	$bin{'aireplay'} . $WIFI . " --arpreplay -b $Host_MAC -d $INJMAC -$FT 1 -m 68 -n 86 -h $FAKE_MAC -x $INJECTRATE",
	$bin{'aireplay'}." $WIFI --interactive -p $FT -c $INJMAC -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE",
	$bin{'aireplay'}." -5 -b $Host_MAC -h $FAKE_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI ",
	$bin{'aireplay'}."--chopchop -b $Host_MAC -h $FAKE_MAC $WIFI ",
	$bin{'aireplay'}."-6 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI ",
	$bin{'aireplay'}." -7 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI",
	$bin{'aireplay'}." $WIFI --arpreplay -b $Host_MAC -d $INJMAC -$FT 1 -m 68 -n 86  -h $Client_MAC -x $INJECTRATE ",
	$bin{'aireplay'}."$WIFI --interactive -p $FT -c $INJMAC -b $Host_MAC $Client_MAC -x $INJECTRATE",
	$bin{'aireplay'}."-5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI",
	$bin{'aireplay'}." -7 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI ",
	$bin{'aireplay'}." --chopchop -h $Client_MAC $WIFI ",
	$bin{'aireplay'}." --interactive -r $dump_path/arp_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI",
	$bin{'aireplay'}."-w $dump_path/$Host_MAC --channel $Host_CHAN -a $WIFI "
);

my @wpaactions=('','','','','');

# Open glade file
# And show main window
	my $MainGladeFile=new Gtk2::GladeXML('airosperl.glade');
	$MainGladeFile->signal_autoconnect_from_package('main');# So we can handle easily signals.
	$MainWindow=$MainGladeFile->get_widget('MainWindow');
	$MainWindow->show_all();
		$MainWindow->signal_connect( delete_event => sub {Gtk2->main_quit();1;});# Program ends when main window closed.

# Define widgets
	# Those are normal widgets (mostly input and labels).	
		$Airserv_INPUT=$MainGladeFile->get_widget('airservng');	
		$Reso_INPUT=$MainGladeFile->get_widget('Resolution');
		$Wifi_INPUT=$MainGladeFile->get_widget('Wifi_Interface');
		$DefaultInput=$MainGladeFile->get_widget('DefaultAirservng');
		$TreeViewWidget=$MainGladeFile->get_widget('WIFI_List');
		$ErrLabel=$MainGladeFile->get_widget('El');
		$Wifi_Interface=$MainGladeFile->get_widget('WifiCombo');

	# Those are windows

		$MdkWindow=$MainGladeFile->get_widget('MdkWindow');
			$MdkWindow->signal_connect( delete_event => sub {$MdkWindow->hide();});
		$SWifiWindow=$MainGladeFile->get_widget('WIFI_Selector');
			$SWifiWindow->signal_connect( delete_event => sub {$SWifiWindow->hide();});
		$FileChooserWindow=$MainGladeFile->get_widget('FileChooser');
			$FileChooserWindow->signal_connect( delete_event => sub {$FileChooserWindow->hide();});
		$FolderChooserWindow=$MainGladeFile->get_widget('FileChooser');
			$FolderChooserWindow->signal_connect( delete_event => sub {$FolderChooserWindow->hide();});
		$ChangeMacWindow=$MainGladeFile->get_widget('ChangeMacWindow');
			$ChangeMacWindow->signal_connect( delete_event => sub {$ChangeMacWindow->hide();});
		$ErrWindow=$MainGladeFile->get_widget('ErrWindow');
			$ErrWindow->signal_connect( delete_event => sub {$ErrWindow->hide();});
		$AboutWindow=$MainGladeFile->get_widget('AboutWindow');
			$AboutWindow->signal_connect( delete_event => sub {$AboutWindow->hide();});
		$WessideWindow=$MainGladeFile->get_widget('WessideWindow');
			$WessideWindow->signal_connect( delete_event => sub {$WessideWindow->hide();});
		$AboutWindow=$MainGladeFile->get_widget('AboutWindow');
			$AboutWindow->signal_connect( delete_event => sub {$AboutWindow->hide();});



# Main Subfunctions
	# Main Window things:
	sub popup_error(){
		$ErrLabel->set_label(@_);
		$ErrWindow->run();
	}

	sub SetWifiInterfaces(){
		my $id=0;my $iter;  
		my $liststore = Gtk2::ListStore->new("Glib::Int","Glib::String");
		if (-x "/bin/ip"){
		for (`ip link|egrep "^[0-9]+"|cut -d ':' -f 2 |awk {'print \$1'} |grep -v lo`){
				chomp;
				$id++;
				$iter = $liststore->append; $liststore->set($iter,0,$id, 1,$_); 
			}
		$Wifi_Interface->set_model($liststore);
		$Wifi_Interface->set_text_column(1);
		}
		else{&popup_error('Your system does not have ip executable. automatic interface detection disabled');}
	}

	sub setmonitormode(){
		system($bin{'ifconfig'}." ".$wifi." down");
		print $bin{'airmon'}." start ".$wifi;
		system($bin{'airmon'}." start ".$wifi);
		system($bin{'ifconfig'}." ".$wifi." up");
	}

	sub create_dump_path(){my $dpath;
		if ($os eq "Windows"){ $dpath=$ENV{'systemdir'}."/tmp/airosperl-".rand('222000')."/";}
		else{$dpath=`mktemp -d`|"/";}
		mkpath $dpath;
		chomp($dpath);
		return $dpath;
	}

	sub GetTerminalOptions(){
		# Set termopts by terminal type. so specify terminal on window.	
	}

	sub runaction(){my @commands=split(/XXX/,$_[0]); foreach my $cmd(@commands){system ("$bin{'terminal'} $termopts{'exec'} $q $cmd $q");	}}

	# Menu items
		# File: connect
	sub setwifidata(){
	  		$TreeView = Gtk2::SimpleList->new_from_treeview($TreeViewWidget,'Name'=>'text','bssid' => 'text', 'Encription' => 'text');
			my @linedata;my $finaldata;
			unlink ("$dump_path/maindump-*.csv");
			my $cmd=$bin{'terminal'}." ".$termopts{'exec'}." \" ".$bin{'airodump'}." $wifi -w $dump_path/maindump \"";system $cmd;
			system("tac $dump_path/maindump-01.csv | sed '1,3d' | tac| sed '1,2d' > $dump_path/maindump-01.csv2");
			open FH, "<$dump_path/maindump-01.csv2";
			my ($bssid,$name,$enc);
			while (<FH>){my @a=split(/,/,$_); $bssid=$a[0]; $name=$a[13]; 
			$enc=$a[6];push (@{$TreeView->{data}}, [$name,$bssid,$enc]); print "$_ dp \n";}
			close FH;
	}

		# File: new 
		sub resetapp(){	Gtk2->main_quit;sleep 1;rmtree $dump_path;system("perl ".abs_path($0)." &");exit(0);}

		# Others reset interface
			sub resetwifi(){system ('killall -9 aireplay-ng airodump-ng > /dev/null &');&setmonitormode();}
		

# Signal handler' subfunctions
#### Menu Items...
	# File :
	sub on_MI_WIFISEL_activate(){
		if ($wifi) {&setwifidata();	$SWifiWindow->show_all;	}
		else{&popup_error('You have to select an interface first');}
	}
    
	sub on_MI_Open_activate(){$action="Open";$FileChooserWindow->show_all;}

	sub on_MI_New_activate(){&resetapp();}

	sub on_MI_Save_activate(){ 
		if ($bssid){$action="Close";
				if (-e "$dump_path/$bssid.cap"){
					$FileChooserWindow->show_all();
					}
				else{&popup_error('No file recorded');}
		}
		else{&popup_error('You haven\'t even selected a network!');}
	}

	sub on_MI_Exit_activate(){Gtk2->main_quit();exit();}

	# Others:
	sub on_MI_ChangeMac_activate(){$ChangeMacWindow->show_all();}
	sub on_MI_Mdk3_activate(){$MdkWindow->show_all();}
	sub on_MI_WessideNg_activate(){$WessideWindow->show_all;}
	sub on_MI_ResetIface_activate(){
		if ($wifi){
			&resetwifi(); 
			&popup_error("Interface $wifi reseted");
		}
		else{
			&popup_error("Interface not selected");
			}
	}
	sub on_MI_About_activate(){$AboutWindow->show_all;}
	sub on_MI_AircrackTest(){&runaction("airmon-ng check");}

# Buttons
  	# Close Buttons
	sub on_WS_BTN_Cancel_clicked(){$SWifiWindow->hide();}
	sub on_ErrOk_clicked(){$ErrWindow->hide();}
	sub on_FC_BTN_Cancel_clicked{$FileChooserWindow->hide();}
	sub on_FoC_BTN_Cancel_clicked{$FolderChooserWindow->hide();}
	sub on_About_BTN_Cancel_clicked{$AboutWindow->hide();}

	# Rest of buttons
	sub on_CMW_Ok_clicked{$ChangeMacWindow->hide();}
	sub on_WS_BTN_Ok_clicked(){$SWifiWindow->hide();}# FIXME: here wifi data should be set.
	sub on_FC_BTN_Ok_clicked(){my $destfile=$FileChooserWindow->get_filename();copy ("$dump_path/*","$destfile/");	}
	sub on_FoC_BTIN_Ok_clicked(){$capfile=$FolderChooserWindow->get_filename();}

# Radio buttons are not working properly with my version of glade so i'll make groups manually (I'd better not used glade at all, but it's a fast way of doing gtk apps).
	# Injection tab
	my $RBI1=$MainGladeFile->get_widget('IN1');
	my $RBI2=$MainGladeFile->get_widget('IN2');
		$RBI2->set_group($RBI1);
	# Fake auth tab
	my $RBFA1=$MainGladeFile->get_widget('FA1');
	my $RBFA2=$MainGladeFile->get_widget('FA2');
		$RBFA2->set_group($RBFA1);
	my $RBFA3=$MainGladeFile->get_widget('FA3');
		$RBFA3->set_group($RBFA1);

	# deauth tab
	my $DA1=$MainGladeFile->get_widget('DA1');
	my $DA2=$MainGladeFile->get_widget('DA2');
		$DA2->set_group($DA1);
	my $DA3=$MainGladeFile->get_widget('DA3');
		$DA3->set_group($DA1);

	# WEP
	my $WEP1=$MainGladeFile->get_widget('WEP1');
	my $WEP2=$MainGladeFile->get_widget('WEP2');
		$WEP2->set_group($WEP1);
	my $WEP3=$MainGladeFile->get_widget('WEP3');
		$WEP3->set_group($WEP1);
	my $WEP4=$MainGladeFile->get_widget('WEP4');
		$WEP4->set_group($WEP1);
	my $WEP5=$MainGladeFile->get_widget('WEP5');
		$WEP5->set_group($WEP1);
	my $WEP6=$MainGladeFile->get_widget('WEP6');
		$WEP6->set_group($WEP1);
	my $WEP7=$MainGladeFile->get_widget('WEP7');
		$WEP7->set_group($WEP1);
	my $WEP8=$MainGladeFile->get_widget('WEP8');
		$WEP8->set_group($WEP1);
	my $WEP9=$MainGladeFile->get_widget('WEP9');
		$WEP9->set_group($WEP1);

	# WPA
	my $WPA1=$MainGladeFile->get_widget('WPA1');
	my $WPA2=$MainGladeFile->get_widget('WPA2');
		$WPA2->set_group($WPA1);

	# Crack
	my $C1=$MainGladeFile->get_widget('C1');
	my $C2=$MainGladeFile->get_widget('C2');
		$C2->set_group($C1);
	my $C3=$MainGladeFile->get_widget('C3');
		$C3->set_group($C1);
	my $C4=$MainGladeFile->get_widget('C4');
		$C4->set_group($C1);

##### Main window items
	sub on_DefaultAirservng_clicked(){$DefaultAirservNg=1 if !$MonitorMode; $MonitorMode="" if $MonitorMode;}
	sub on_MonitorMode_toggled(){$MonitorMode=1 if !$MonitorMode; $MonitorMode="" if $MonitorMode;}

	sub on_apply_clicked{# Apply main configuration.
		$airservng_addr=$Airserv_INPUT->get_text(); 
		$wifi=$Wifi_INPUT->get_text();
		$reso=$Reso_INPUT->get_text();
		if ($DefaultAirservNg){$airservng_addr="127.0.0.1:666";}else{$airservng_addr="";}
		if ($MonitorMode){&setmonitormode($wifi);}
		if ($airservng_addr ne ""){
			if ($wifi eq ""){$wifi=$airservng_addr;}
			else{&popup_error('You entered a wifi interface and airserv-ng. Airserv-ng will be used.');$wifi=$airservng_addr;}
		}
	}

	sub on_Wpaapply_clicked(){
		my $btnn=0;my $selbutton;	my $WPA1=$MainGladeFile->get_widget('WPA1');my $group=$WPA1->get_group();
		foreach my $btn (@$group){$btnn++;$selbutton=$btnn if $btn->get_active;}
		&runaction($wpaactions[$selbutton]);system "echo executing $wepactions[$selbutton]";
	}

	sub on_Wepapply_clicked(){
		my $btnn=0;my $selbutton;	my $WEP1=$MainGladeFile->get_widget('WEP1');my $group=$WEP1->get_group();
		foreach my $btn (@$group){$btnn++;$selbutton=$btnn if $btn->get_active;}
		&runaction($wepactions[$selbutton]);system "echo executing $wepactions[$selbutton]";
	}


	sub on_MW_group_changed(){# my ($widget,$commands)=@_; $mwcmd=$commands; } 	
}
#### Main program.
# Get term options and set them on $termopts hash. This is a future todo, not required for now. 
#%termopts=&GetTerminalOptions();

# Set wifi interfaces in main window.
&SetWifiInterfaces();
# Main application loop
Gtk2->main;

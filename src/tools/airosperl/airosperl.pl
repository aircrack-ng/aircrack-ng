#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  airosperl.pl
#
#        USAGE:  airosperl  
#
#         BUGS:  When selecting a new wifi network, screen keeps white.
#  DESCRIPTION:  Airoscript perl gui with Gtk(glade) interface
# REQUIREMENTS:  airosperl.glade
#       AUTHOR:  David Francos Cuartero (XayOn), yo.orco@gmail.com
#      CREATED:  01/03/09 19:38:55
#===============================================================================

use strict;use warnings;no warnings 'uninitialized';
use Gtk2 -init; use Gtk2::GladeXML; use Gtk2::SimpleList; 
use File::Path;use File::Copy; use Cwd 'abs_path';

# Get config.
if (!-e $ENV{'HOME'}.".airosperl.conf"){require ("/etc/airosperl.conf") or die "Could not open conffile";}
else{require ($ENV{'HOME'}.".airosperl.conf") or die "Could not open conffile";}
our ($apppath,%termopts,%bin,$q,$FT,$FAKE_MAC,$INJMAC,$INJECTRATE,$TKIPTUN_MAX_PL,$TKIPTUN_MIN_PL,$Client_IP,$Host_IP); # Those comes from airosperl.conf

# Define variables
	my ($bssid,$airservng_addr,$wifi,$DefaultAirservNG,,$capfile,$final,$TreeVie,$TreeView,$action,$os,$mwcmd,$Client_MAC,$FRAG_CLIENT_IP,$FRAG_HOST_IP,$Host_CHAN,,@alternative_wepactions,@wepactions,@wpaactions,@injactions,@crackactions,@fakeactions,@deauthactions,$Host_SSID,$WIFI,$Host_MAC,$Thing_Mac);# Standard
	my ($ErrLabel,$Airserv_INPUT,$DefaultInput,$Wifi_INPUT,$MonitorMode,$TreeViewWidget,$Wifi_Interface,$model,$IN_ClientMac,$MonModeInput);# Widgets
	our ($MainWindow, $FileChooserWindow, $SWifiWindow,$ErrWindow,$ChangeMacWindow,$MdkWindow,$WessideWindow,$FolderChooserWindow,$AboutWindow,$ClientSelWindow,$ConfigWindow); # Windows

if (-e "/bin/uname"){$os="Linux";}else { if (-e $ENV{'systemroot'}){$os="Windows"}}

# Create dump_path before setting actions...
	my $dump_path=&create_dump_path();

# Open glade file and show main window
	my $MainGladeFile=new Gtk2::GladeXML($apppath.'airosperl.glade');
	$MainGladeFile->signal_autoconnect_from_package('main');# So we can handle easily signals.
	$MainWindow=$MainGladeFile->get_widget('MainWindow');
	$MainWindow->signal_connect( delete_event => sub {Gtk2->main_quit();1;});# Program ends when main window closed.
	$MainWindow->show_all();

# Define widgets
	# Those are normal widgets (mostly input and labels).	
		$Airserv_INPUT=$MainGladeFile->get_widget('airservng');	
		$IN_ClientMac=$MainGladeFile->get_widget('IN_ClientMac');	
		$Wifi_INPUT=$MainGladeFile->get_widget('Wifi');
		$DefaultInput=$MainGladeFile->get_widget('DefaultAirservng');
		$MonModeInput=$MainGladeFile->get_widget('MonitorMode');
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
		$ClientSelWindow=$MainGladeFile->get_widget('ClientSelWindow');
			$ClientSelWindow->signal_connect( delete_event => sub {$ClientSelWindow->hide();});
		$ConfigWindow=$MainGladeFile->get_widget('ConfigWindow');
			$ConfigWindow->signal_connect( delete_event => sub {$ConfigWindow->hide();});
	

# Main Subfunctions
	# Main Window things:
	sub popup_error(){$ErrLabel->set_label(@_);	$ErrWindow->run();}

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
		system($bin{'airmon'}." start ".$wifi);
		system($bin{'ifconfig'}." ".$wifi." up");
	}

	sub create_dump_path(){my $dpath;
		if ($os eq "Windows"){ $dpath=$ENV{'systemdir'}."/tmp/airosperl-".rand('222000')."/";}
		else{$dpath=`mktemp -d`|"/";} chomp($dpath);mkpath $dpath;return $dpath;
	}

	sub GetTerminalOptions(){
	#	switch ($TERM){
			#case "xterm"{
				%termopts=(''=>'');
	#		}
	#	}
	#	return %termopts;
	}

	sub runaction(){my @commands=split(/XXX/,$_[1]);if (!$WIFI){&popup_error('You have to select a wifi card first');return;} foreach my $cmd(@commands){system ("$bin{'terminal'} $termopts{$_[0]} $termopts{'exec'} $q $cmd $q &");}}

	sub setattacks(){# Note: Last in airoscript must be first here.
		@wepactions=( 
                        $bin{'aireplay'}." --interactive -r $dump_path/arp_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI",
                        $bin{'aireplay'}." --chopchop -h $Client_MAC $WIFI ",
                        $bin{'aireplay'}." -5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI",
                        $bin{'aireplay'}." $WIFI --arpreplay -b $Host_MAC -d $INJMAC -t 1 -m 68 -n 86  -h $Client_MAC -x $INJECTRATE ",
                        $bin{'aireplay'}." -7 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI",
                        $bin{'aireplay'}." -6 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI ",
                        $bin{'aireplay'}." --chopchop -b $Host_MAC -h $FAKE_MAC $WIFI ",
                        $bin{'aireplay'}." -5 -b $Host_MAC -h $FAKE_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI ",
                        $bin{'aireplay'} ." ". $WIFI . " --arpreplay -b $Host_MAC -d $INJMAC -f 1 -m 68 -n 86 -h $FAKE_MAC -x $INJECTRATE");
# FIXME : Those are selected in checkbox, if checkbox selected, execute this instead of the others... This can be in wepapply code.
		@alternative_wepactions=(
                        $bin{'aireplay'}." -7 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI ",
                        $bin{'aireplay'}." $WIFI --interactive -p $FT -c $INJMAC -b $Host_MAC $Client_MAC -x $INJECTRATE",
                        $bin{'aireplay'}." $WIFI --interactive -p $FT -c $INJMAC -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE",
		);

		@wpaactions=(
			$bin{'tkiptun'}. " -h $FAKE_MAC -a $Host_MAC -m $TKIPTUN_MIN_PL -n $TKIPTUN_MAX_PL $WIFI",
                        $bin{'airodump'}." -w $dump_path/$Host_MAC --channel $Host_CHAN -a $WIFI"
		);

		@fakeactions=(
		        $bin{'aireplay'}." --fakeauth 5 -o 10 -q 1 -e $Host_SSID -a $Host_MAC -h $FAKE_MAC $WIFI ",
                        $bin{'aireplay'}." --fakeauth 0 -e $Host_SSID -a $Host_MAC -h $FAKE_MAC $WIFI ",
                        $bin{'aireplay'}." --fakeauth 6000 -o 1 -q 10 -e $Host_SSID -a $Host_MAC -h $FAKE_MAC $WIFI "

		);

		@deauthactions=(
			"",
			"",
			""
		);

		@injactions=(
			$bin{'arpforge'}." -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $dump_path/frag_$Host_MAC.cap".
			"XXX".
			$bin{'aireplay'}." -2 -r $dump_path/frag_$Thing_Mac.cap -h $FAKE_MAC -x $INJECTRATE $WIFI",

			""
		);

		@crackactions=(
			"",
			"",
			""
		);

	}

	# Menu items
		# File: connect
	sub setwifiaps(){
	  		$TreeView = Gtk2::SimpleList->new_from_treeview($TreeViewWidget,'Name'=>'text','Chan'=>'text','bssid' => 'text', 'Encription' => 'text');
			$TreeView->signal_connect (row_activated => sub { my ($sl, $path, $column) = @_; my $row_ref = $sl->get_row_data_from_path ($path);$Host_MAC=@$row_ref[2];$Host_SSID=@$row_ref[0];$Host_CHAN=@$row_ref[1];print @$row_ref;});
			my @linedata;my $finaldata;
			unlink ("$dump_path/maindump-*.csv");
			my $cmd=$bin{'terminal'}." ".$termopts{'exec'}." \" ".$bin{'airodump'}." $wifi -w $dump_path/maindump \"";system $cmd;
			system("tac $dump_path/maindump-01.csv | sed '1,3d' | tac| sed '1,2d'|cut -d, -f1,4,6,14 > $dump_path/maindump-01.csv2");
			open FH, "<$dump_path/maindump-01.csv2";
			my ($bssid,$name,$enc,$chan);
			while (<FH>){
			my @a=split(/,/,$_);print @a;
			$bssid=$a[1]; $chan=$a[0];$name=$a[3]; 	$enc=$a[2];
			chomp ($bssid,$chan,$name,$enc);
			push (@{$TreeView->{data}}, [$name,$bssid,$chan,$enc]); print "$_ dp \n";}
			close FH;
	}

		# File: new 
		sub resetapp(){	Gtk2->main_quit;sleep 1;rmtree $dump_path;system("perl ".abs_path($0)." &");exit(0);}

		# Others reset interface
			sub resetwifi(){system ('killall -9 aireplay-ng airodump-ng > /dev/null &');&setmonitormode();}
		
		# File: Select clients
		sub setwificlients(){# FIXME This doesnt work... failed in the system calls.
	  		$TreeView = Gtk2::SimpleList->new_from_treeview($TreeViewWidget,'Name'=>'text','bssid' => 'text', 'Encription' => 'text');
			$TreeView->signal_connect (row_activated => sub { my ($sl, $path, $column) = @_; my $row_ref = $sl->get_row_data_from_path ($path);$Client_MAC=@$row_ref[1];});

			my @linedata;
			my $finaldata;	

			unlink ("$dump_path/maindump-*.csv");

			my $cmd=$bin{'terminal'}." ".$termopts{'exec'}." \" ".$bin{'airodump'}." $wifi -w $dump_path/maindump \"";
			print STDERR "\nExecuting $cmd\n";
			system $cmd;

			system("tac $dump_path/maindump-01.csv  | sed '1,3d' | tac| sed '1,2d' > $dump_path/maindump-01.csv2");
			system("cat $dump_path/maindump-01.csv2 | grep -a \"0.:..:..:..:..\" | awk \'{ print \$1 }\'| grep -a -v 00:00:00:00 > $dump_path/maindump-01.csv");

			open FH, "<$dump_path/maindump-01.csv";	my $bssid;

			while (<FH>){
				$bssid=`echo \"$_\" |awk '{split(\$1, info, "," )print info[1]  }'`; 
				push (@{$TreeView->{data}}, ['',$bssid,'']);
			}

			close FH;
		}

# Signal handler' subfunctions
#### Menu Items...
	# File :
	sub on_MI_WIFISEL_activate(){
		if ($wifi) {&setwifiaps();	$SWifiWindow->show_all;	}
		else{&popup_error('You have to select an interface first');}
	}
    
	sub on_MI_Open_activate(){$action="Open";$FileChooserWindow->show_all;}

	sub on_MI_New_activate(){&resetapp();}

	sub on_MI_Save_activate(){ 
		if ($Host_MAC){$action="Close";
				if (-e "$dump_path/$Host_MAC.cap"){
					$FileChooserWindow->show_all();
					}
				else{&popup_error('No file recorded');}
		}
		else{&popup_error('You haven\'t even selected a network!');}
	}

	sub on_MI_Exit_activate(){Gtk2->main_quit();exit();}

	sub on_MI_Client_activate{&setwificlients();$ClientSelWindow->show_all;}

	# Others:
	sub on_MI_ChangeMac_activate(){$ChangeMacWindow->show_all();}
	sub on_MI_Mdk3_activate(){$MdkWindow->show_all;}
	sub on_MI_WessideNg_activate(){$WessideWindow->show_all;}
	sub on_MI_ResetIface_activate(){if ($wifi){&resetwifi(); &popup_error("Interface $wifi reseted");}else{&popup_error("Interface not selected");}}
	sub on_MI_About_activate(){$AboutWindow->show_all;}
	sub on_MI_AircrackTest_activate(){&runaction('hold',"airmon-ng check");}
	sub on_MI_WL_activate{
		&popup_error("Wordlist generated at".$ENV{'HOME'}.$Host_MAC."wl");
		system ("airoswordlist -m $Host_MAC -s $Host_SSID -filename  ".$ENV{'HOME'}.$Host_MAC.".wl"." &");

	}
	# Configure
	sub on_MI_Configure_activate(){
		$ConfigWindow->show_all;	
	}

# Buttons
  	# Close Buttons
	sub on_WS_BTN_Cancel_clicked(){$SWifiWindow->hide();}
	sub on_ErrOk_clicked(){$ErrWindow->hide();}
	sub on_FC_BTN_Cancel_clicked{$FileChooserWindow->hide();}
	sub on_FoC_BTN_Cancel_clicked{$FolderChooserWindow->hide();}
	sub on_About_BTN_Cancel_clicked{$AboutWindow->hide();}
	sub on_CS_BTN_Ok_clicked(){&setattacks();$ClientSelWindow->hide();}

	# Rest of buttons
	sub on_CMW_Ok_clicked{$ChangeMacWindow->hide();}
	sub on_WS_BTN_Ok_clicked(){&setattacks();	$SWifiWindow->hide();}
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
	sub on_DefaultAirservng_toggled(){$DefaultAirservNG=$DefaultInput->get_active();}
	sub on_MonitorMode_toggled(){$MonitorMode=$MonModeInput->get_active();}

	sub on_apply_clicked{# Apply main configuration.
		$airservng_addr=$Airserv_INPUT->get_text(); 
		$wifi=$Wifi_INPUT->get_text(); $WIFI=$wifi;
		if ($DefaultAirservNG){$airservng_addr="127.0.0.1:666";}else{$airservng_addr="";}
		if ($MonitorMode){&setmonitormode($wifi);}
		if ($airservng_addr ne ""){
			if ($wifi eq ""){$wifi=$airservng_addr;}
			else{&popup_error('You entered a wifi interface and airserv-ng. Airserv-ng will be used.');$wifi=$airservng_addr;}
		}
	}

	sub on_Wpaapply_clicked(){
		my $btnn=0;my $selbutton;	my $WPA1=$MainGladeFile->get_widget('WPA1');my $group=$WPA1->get_group();
		foreach my $btn (@$group){$selbutton=$btnn if $btn->get_active;$btnn++;}
		&runaction('',$wpaactions[$selbutton]);print " executing ($selbutton) $wpaactions[$selbutton] ";
	}

	sub on_Wepapply_clicked(){
		my @excluded=(1,2,3); my $_excluded; # FIXME : Those are not really that, and I've got to change the checkbuttons names.
		my $btnn=0;my $selbutton;	my $WEP1=$MainGladeFile->get_widget('WEP1');my $group=$WEP1->get_group();
		foreach my $btn (@$group){
			print STDERR "We are on button $btnn, checking if selected...";
			$selbutton=$btnn if $btn->get_active;
			print STDERR "yes\n" if $btn->get_active;
			$btnn++; 
		}
		foreach (@excluded){
			if ( $btnn == $_ ) {
				# So, check if button is checked, if so, set _excluded to true
				my $checkbutton=$MainGladeFile->get_widget("CHKWEP".$_);
				if ($checkbutton->checked){$_excluded=1;}
			}
		}

		&popup_error('You should launch a fake attack now');


		if ($_excluded){
			print STDERR "Executing alternative_wepactions[$selbutton] ($selbutton)\n";
			&runaction('',$alternative_wepactions[$selbutton]);
		} else {
			print STDERR "Executing $wepactions[$selbutton] ($selbutton)\n";
			&runaction('',$wepactions[$selbutton]);

		}
	}


	sub on_Fakeapply_clicked(){
		my $btnn=0;my $selbutton;	my $FA1=$MainGladeFile->get_widget('FA1');my $group=$FA1->get_group();
		foreach my $btn (@$group){$selbutton=$btnn if $btn->get_active;$btnn++;}
		print "Executing $fakeactions[$selbutton] ($selbutton)\n";&runaction('',$fakeactions[$selbutton]);
	}


	sub on_Deauthapply_clicked{ # TODO This should do same as others but, if button=2, get text from text entry and assign foo stuff to bar.
		my $btnn=0;my $selbutton;	my $IN1=$MainGladeFile->get_widget('IN1');my $group=$IN1->get_group();
		foreach my $btn (@$group){$selbutton=$btnn if $btn->get_active;$btnn++;}
		if ($selbutton == 2){
			
		}
		else{
			print "Executing $injactions[$selbutton]\n";&runaction('',$injactions[$selbutton]);
		}
	}


	sub on_Injectionapply_clicked(){
		my $btnn=0;my $selbutton;	
		my $IN1=$MainGladeFile->get_widget('IN1');my $group=$IN1->get_group();
		foreach my $btn (@$group){$selbutton=$btnn if $btn->get_active;$btnn++;}
		$Thing_Mac=$IN_ClientMac->get_text();$Thing_Mac=$Host_MAC if !$Thing_Mac;
		print "Executing $injactions[$selbutton]\n";&runaction('',$injactions[$selbutton]);
	}


	sub on_Crackapply_clicked(){ 
		my $btnn=0;
		my $selbutton;	
		my $IN1=$MainGladeFile->get_widget('IN1');
		my $group=$IN1->get_group();

		foreach my $btn (@$group){$selbutton=$btnn if $btn->get_active;$btnn++;}
			if ($selbutton == 2){
				my $INWIDGET=$MainGladeFile->get_widget('');
				my $text=$INWIDGET->get_text();
				print "Executing $crackactions[$selbutton]\n with text $text";
				&runaction('',$injactions[$selbutton]." ".$text);
			} else {
				print "Executing $injactions[$selbutton]\n";
				&runaction('',$injactions[$selbutton]);
			}
	}


	sub on_config_clicked{system('airosconf update');$ConfigWindow->hide();}

#%termopts=&GetTerminalOptions();
&SetWifiInterfaces();
Gtk2->main;


																			



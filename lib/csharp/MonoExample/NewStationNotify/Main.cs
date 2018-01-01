// License: BSD/LGPL
// Copyright (C) 2011-2018 Thomas d'Otreppe
// 
using System.Threading;
using WirelessPanda.Readers;
using WirelessPanda;
using System.Collections;
using System.Collections.Generic;
using System;

namespace NewStationNotify
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			Console.WriteLine(DateTime.Now + " - Program started");
			Reader r = new UniversalReader("/home/user/dump-01.csv");
			
			List<Station> stationList = new List<Station>();
			
			// Read the file
			r.Read();
			
			// Add existing stations to the list
			stationList.AddRange(r.Stations);
				
			while (true) {
				// Sleep 5 seconds
				Thread.Sleep(5000);
			
				Console.WriteLine(DateTime.Now + " - Checking for updates");
				
				// Update file
				r.Read();
				
				// Get station list
				foreach(Station sta in r.Stations) {
					
					// If new station, update us
					if (!stationList.Contains(sta)) {
						stationList.Add(sta);
						
						// Display it on the command line
						Console.WriteLine(DateTime.Now + " - New station: " + sta.StationMAC);
						
						// Display it as a notification
						Notification.Notify(sta.BSSID, sta.StationMAC);
					}
				}
			}
			
		}
	}
}

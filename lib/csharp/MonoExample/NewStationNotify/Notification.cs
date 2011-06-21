// License: BSD
// Copyright (C) 2011 Thomas d'Otreppe
using System;
using System.Collections.Generic;
using NDesk.DBus;
using org.freedesktop;
	
namespace NewStationNotify
{
	public class Notification
	{
		public Notification ()
		{
		}
		
		/// <summary>
		/// Shows a notification on the screen. This has been tested on a N900 and will probably not work with anything else but it can be used as a base.
		/// </summary>
		public static void Notify(String BSSID, String staMac) {
			Bus bus = Bus.Session;

			Notifications nf = bus.GetObject<Notifications> ("org.freedesktop.Notifications", new ObjectPath ("/org/freedesktop/Notifications"));

			Dictionary<string,object> hints = new Dictionary<string,object> ();
			
			if (string.IsNullOrEmpty(BSSID)) {
				
				nf.Notify ("Notification", 0, "control_bluetooth_paired", "New unassociated station", staMac, new string[0], hints, 0);
			} else {
				nf.Notify ("Notification", 0, "control_bluetooth_paired", "New associated station", staMac + " (AP: " + BSSID + ")", new string[0], hints, 0);
			}
			/*
			// Ugly hack for the N900 to notify the user since this can't be done with dbus-send
			// because it does not support empty array.
			StreamWriter sw = new StreamWriter("/home/user/notify.py");
			if (string.IsNullOrEmpty(BSSID)) {
				
				sw.WriteLine("import dbus\n" +
					"bus = dbus.SessionBus()\n" +
					"proxy = bus.get_object('org.freedesktop.Notifications', '/org/freedesktop/Notifications')\n" +
					"interface = dbus.Interface(proxy,dbus_interface='org.freedesktop.Notifications')\n" +
					"interface.Notify('Notification', 0, 'control_bluetooth_paired', 'New unassociated station', '{0}', [], {{}}, 0)", staMac);
			} else {
				sw.WriteLine("import dbus\n" +
					"bus = dbus.SessionBus()\n" +
					"proxy = bus.get_object('org.freedesktop.Notifications', '/org/freedesktop/Notifications')\n" +
					"interface = dbus.Interface(proxy,dbus_interface='org.freedesktop.Notifications')\n" +
					"interface.Notify('Notification', 0, 'control_bluetooth_paired', 'New associated station', '{0} is associated to {1}', [], {{}}, 0)", staMac, BSSID);
			}
			sw.Close();
			Process p = new Process();
			p.StartInfo.UseShellExecute = false;
			p.StartInfo.FileName = "/usr/bin/python";
			p.StartInfo.Arguments = "/home/user/notify.py";
			p.Start();
			p.WaitForExit();
			FileInfo f = new FileInfo("/home/user/notify.py");
			f.Delete();
			*/
		}
	}
}


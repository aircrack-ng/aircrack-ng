// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Text;
using System.Collections.Generic;

namespace NDesk.DBus
{
	public class BadAddressException : Exception
	{
		public BadAddressException (string reason) : base (reason) {}
	}

	class AddressEntry
	{
		public string Method;
		public IDictionary<string,string> Properties = new Dictionary<string,string> ();

		public override string ToString ()
		{
			StringBuilder sb = new StringBuilder ();
			sb.Append (Method);
			sb.Append (':');

			bool first = true;
			foreach (KeyValuePair<string,string> prop in Properties) {
				if (first)
					first = false;
				else
					sb.Append (',');

				sb.Append (prop.Key);
				sb.Append ('=');
				sb.Append (Escape (prop.Value));
			}

			return sb.ToString ();
		}

		static string Escape (string str)
		{
			if (str == null)
				return String.Empty;

			StringBuilder sb = new StringBuilder ();
			int len = str.Length;

			for (int i = 0 ; i != len ; i++) {
				char c = str[i];

				//everything other than the optionally escaped chars _must_ be escaped
				if (Char.IsLetterOrDigit (c) || c == '-' || c == '_' || c == '/' || c == '\\' || c == '.')
					sb.Append (c);
				else
					sb.Append (Uri.HexEscape (c));
			}

			return sb.ToString ();
		}

		static string Unescape (string str)
		{
			if (str == null)
				return String.Empty;

			StringBuilder sb = new StringBuilder ();
			int len = str.Length;
			int i = 0;
			while (i != len) {
				if (Uri.IsHexEncoding (str, i))
					sb.Append (Uri.HexUnescape (str, ref i));
				else
					sb.Append (str[i++]);
			}

			return sb.ToString ();
		}


		public static AddressEntry Parse (string s)
		{
			AddressEntry entry = new AddressEntry ();

			string[] parts = s.Split (':');

			if (parts.Length < 2)
				throw new BadAddressException ("No colon found");
			if (parts.Length > 2)
				throw new BadAddressException ("Too many colons found");

			entry.Method = parts[0];

			foreach (string propStr in parts[1].Split (',')) {
				parts = propStr.Split ('=');

				if (parts.Length < 2)
					throw new BadAddressException ("No equals sign found");
				if (parts.Length > 2)
					throw new BadAddressException ("Too many equals signs found");

				entry.Properties[parts[0]] = Unescape (parts[1]);
			}

			return entry;
		}
	}

	static class Address
	{
		//(unix:(path|abstract)=.*,guid=.*|tcp:host=.*(,port=.*)?);? ...
		public static AddressEntry[] Parse (string addresses)
		{
			if (addresses == null)
				throw new ArgumentNullException (addresses);

			List<AddressEntry> entries = new List<AddressEntry> ();

			foreach (string entryStr in addresses.Split (';'))
				entries.Add (AddressEntry.Parse (entryStr));

			return entries.ToArray ();
		}

		const string SYSTEM_BUS_ADDRESS = "unix:path=/var/run/dbus/system_bus_socket";
		public static string System
		{
			get {
				string addr = Environment.GetEnvironmentVariable ("DBUS_SYSTEM_BUS_ADDRESS");

				if (String.IsNullOrEmpty (addr))
					addr = SYSTEM_BUS_ADDRESS;

				return addr;
			}
		}

		public static string Session
		{
			get {
				return Environment.GetEnvironmentVariable ("DBUS_SESSION_BUS_ADDRESS");
			}
		}

		public static string Starter
		{
			get {
				return Environment.GetEnvironmentVariable ("DBUS_STARTER_ADDRESS");
			}
		}

		public static string StarterBusType
		{
			get {
				return Environment.GetEnvironmentVariable ("DBUS_STARTER_BUS_TYPE");
			}
		}
	}
}

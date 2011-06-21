// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Globalization;

namespace NDesk.DBus.Authentication
{
	enum ClientState
	{
		WaitingForData,
		WaitingForOK,
		WaitingForReject,
	}

	enum ServerState
	{
		WaitingForAuth,
		WaitingForData,
		WaitingForBegin,
	}

	class SaslClient
	{
		protected Connection conn;

		protected SaslClient ()
		{
		}

		public SaslClient (Connection conn)
		{
			this.conn = conn;
		}

		public void Run ()
		{
			StreamReader sr = new StreamReader (conn.Transport.Stream, Encoding.ASCII);
			StreamWriter sw = new StreamWriter (conn.Transport.Stream, Encoding.ASCII);

			sw.NewLine = "\r\n";

			string str = conn.Transport.AuthString ();
			byte[] bs = Encoding.ASCII.GetBytes (str);

			string authStr = ToHex (bs);

			sw.WriteLine ("AUTH EXTERNAL {0}", authStr);
			sw.Flush ();

			string ok_rep = sr.ReadLine ();

			string[] parts;
			parts = ok_rep.Split (' ');

			if (parts.Length < 1 || parts[0] != "OK")
				throw new Exception ("Authentication error: AUTH EXTERNAL was not OK: \"" + ok_rep + "\"");

			/*
			string guid = parts[1];
			byte[] guidData = FromHex (guid);
			uint unixTime = BitConverter.ToUInt32 (guidData, 0);
			Console.Error.WriteLine ("guid: " + guid + ", " + "unixTime: " + unixTime + " (" + UnixToDateTime (unixTime) + ")");
			*/

			sw.WriteLine ("BEGIN");
			sw.Flush ();
		}

		//From Mono.Unix.Native.NativeConvert
		//should these methods use long or (u)int?
		public static DateTime UnixToDateTime (long time)
		{
			DateTime LocalUnixEpoch = new DateTime (1970, 1, 1);
			TimeSpan LocalUtcOffset = TimeZone.CurrentTimeZone.GetUtcOffset (DateTime.UtcNow);
			return LocalUnixEpoch.AddSeconds ((double) time + LocalUtcOffset.TotalSeconds);
		}

		public static long DateTimeToUnix (DateTime time)
		{
			DateTime LocalUnixEpoch = new DateTime (1970, 1, 1);
			TimeSpan LocalUtcOffset = TimeZone.CurrentTimeZone.GetUtcOffset (DateTime.UtcNow);
			TimeSpan unixTime = time.Subtract (LocalUnixEpoch) - LocalUtcOffset;

			return (long) unixTime.TotalSeconds;
		}

		//From Mono.Security.Cryptography
		//Modified to output lowercase hex
		static public string ToHex (byte[] input)
		{
			if (input == null)
				return null;

			StringBuilder sb = new StringBuilder (input.Length * 2);
			foreach (byte b in input) {
				sb.Append (b.ToString ("x2", CultureInfo.InvariantCulture));
			}
			return sb.ToString ();
		}

		//From Mono.Security.Cryptography
		static private byte FromHexChar (char c)
		{
			if ((c >= 'a') && (c <= 'f'))
				return (byte) (c - 'a' + 10);
			if ((c >= 'A') && (c <= 'F'))
				return (byte) (c - 'A' + 10);
			if ((c >= '0') && (c <= '9'))
				return (byte) (c - '0');
			throw new ArgumentException ("Invalid hex char");
		}

		//From Mono.Security.Cryptography
		static public byte[] FromHex (string hex)
		{
			if (hex == null)
				return null;
			if ((hex.Length & 0x1) == 0x1)
				throw new ArgumentException ("Length must be a multiple of 2");

			byte[] result = new byte [hex.Length >> 1];
			int n = 0;
			int i = 0;
			while (n < result.Length) {
				result [n] = (byte) (FromHexChar (hex [i++]) << 4);
				result [n++] += FromHexChar (hex [i++]);
			}
			return result;
		}
	}
}

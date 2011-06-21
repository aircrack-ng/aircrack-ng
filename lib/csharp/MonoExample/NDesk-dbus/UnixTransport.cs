// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.IO;
using Mono.Unix;

namespace NDesk.DBus.Transports
{
	abstract class UnixTransport : Transport
	{
		public override void Open (AddressEntry entry)
		{
			string path;
			bool abstr;

			if (entry.Properties.TryGetValue ("path", out path))
				abstr = false;
			else if (entry.Properties.TryGetValue ("abstract", out path))
				abstr = true;
			else
				throw new Exception ("No path specified for UNIX transport");

			Open (path, abstr);
		}

		public override string AuthString ()
		{
			long uid = UnixUserInfo.GetRealUserId ();

			return uid.ToString ();
		}

		public abstract void Open (string path, bool @abstract);
	}
}

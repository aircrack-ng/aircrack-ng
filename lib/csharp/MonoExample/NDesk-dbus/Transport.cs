// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.IO;

namespace NDesk.DBus.Transports
{
	abstract class Transport
	{
		public static Transport Create (AddressEntry entry)
		{
			switch (entry.Method) {
				case "tcp":
				{
					Transport transport = new SocketTransport ();
					transport.Open (entry);
					return transport;
				}
#if !PORTABLE
				case "unix":
				{
					//Transport transport = new UnixMonoTransport ();
					Transport transport = new UnixNativeTransport ();
					transport.Open (entry);
					return transport;
				}
#endif
				default:
					throw new NotSupportedException ("Transport method \"" + entry.Method + "\" not supported");
			}
		}

		protected Connection connection;

		public Connection Connection
		{
			get {
				return connection;
			} set {
				connection = value;
			}
		}

		//TODO: design this properly

		//this is just a temporary solution
		public Stream Stream;
		public long SocketHandle;
		public abstract void Open (AddressEntry entry);
		public abstract string AuthString ();
		public abstract void WriteCred ();
	}
}

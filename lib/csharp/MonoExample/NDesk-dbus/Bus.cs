// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using org.freedesktop.DBus;

namespace NDesk.DBus
{
	public sealed class Bus : Connection
	{
		static Bus systemBus = null;
		public static Bus System
		{
			get {
				if (systemBus == null) {
					try {
						if (Address.StarterBusType == "system")
							systemBus = Starter;
						else
							systemBus = Bus.Open (Address.System);
					} catch (Exception e) {
						throw new Exception ("Unable to open the system message bus.", e);
					}
				}

				return systemBus;
			}
		}

		static Bus sessionBus = null;
		public static Bus Session
		{
			get {
				if (sessionBus == null) {
					try {
						if (Address.StarterBusType == "session")
							sessionBus = Starter;
						else
							sessionBus = Bus.Open (Address.Session);
					} catch (Exception e) {
						throw new Exception ("Unable to open the session message bus.", e);
					}
				}

				return sessionBus;
			}
		}

		//TODO: parsing of starter bus type, or maybe do this another way
		static Bus starterBus = null;
		public static Bus Starter
		{
			get {
				if (starterBus == null) {
					try {
						starterBus = Bus.Open (Address.Starter);
					} catch (Exception e) {
						throw new Exception ("Unable to open the starter message bus.", e);
					}
				}

				return starterBus;
			}
		}

		//public static readonly Bus Session = null;

		//TODO: use the guid, not the whole address string
		//TODO: consider what happens when a connection has been closed
		static Dictionary<string,Bus> buses = new Dictionary<string,Bus> ();

		//public static Connection Open (string address)
		public static new Bus Open (string address)
		{
			if (address == null)
				throw new ArgumentNullException ("address");

			if (buses.ContainsKey (address))
				return buses[address];

			Bus bus = new Bus (address);
			buses[address] = bus;

			return bus;
		}

		IBus bus;

		static readonly string DBusName = "org.freedesktop.DBus";
		static readonly ObjectPath DBusPath = new ObjectPath ("/org/freedesktop/DBus");

		public Bus (string address) : base (address)
		{
			bus = GetObject<IBus> (DBusName, DBusPath);

			/*
					bus.NameAcquired += delegate (string acquired_name) {
			Console.WriteLine ("NameAcquired: " + acquired_name);
		};
		*/
			Register ();
		}

		//should this be public?
		//as long as Bus subclasses Connection, having a Register with a completely different meaning is bad
		void Register ()
		{
			if (unique_name != null)
				throw new Exception ("Bus already has a unique name");

			unique_name = bus.Hello ();
		}

		public ulong GetUnixUser (string name)
		{
			return bus.GetConnectionUnixUser (name);
		}

		public RequestNameReply RequestName (string name)
		{
			return RequestName (name, NameFlag.None);
		}

		public RequestNameReply RequestName (string name, NameFlag flags)
		{
			return bus.RequestName (name, flags);
		}

		public ReleaseNameReply ReleaseName (string name)
		{
			return bus.ReleaseName (name);
		}

		public bool NameHasOwner (string name)
		{
			return bus.NameHasOwner (name);
		}

		public StartReply StartServiceByName (string name)
		{
			return StartServiceByName (name, 0);
		}

		public StartReply StartServiceByName (string name, uint flags)
		{
			return bus.StartServiceByName (name, flags);
		}

		internal protected override void AddMatch (string rule)
		{
			bus.AddMatch (rule);
		}

		internal protected override void RemoveMatch (string rule)
		{
			bus.RemoveMatch (rule);
		}

		string unique_name = null;
		public string UniqueName
		{
			get {
				return unique_name;
			} set {
				if (unique_name != null)
					throw new Exception ("Unique name can only be set once");
				unique_name = value;
			}
		}
	}
}

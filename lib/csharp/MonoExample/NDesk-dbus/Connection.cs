// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Reflection;

namespace NDesk.DBus
{
	using Authentication;
	using Transports;

	public partial class Connection
	{
		//TODO: reconsider this field
		Stream ns = null;

		Transport transport;
		internal Transport Transport {
			get {
				return transport;
			} set {
				transport = value;
			}
		}

		protected Connection () {}

		internal Connection (Transport transport)
		{
			this.transport = transport;
			transport.Connection = this;

			//TODO: clean this bit up
			ns = transport.Stream;
		}

		//should this be public?
		internal Connection (string address)
		{
			OpenPrivate (address);
			Authenticate ();
		}

		/*
		bool isConnected = false;
		public bool IsConnected
		{
			get {
				return isConnected;
			}
		}
		*/

		//should we do connection sharing here?
		public static Connection Open (string address)
		{
			Connection conn = new Connection ();
			conn.OpenPrivate (address);
			conn.Authenticate ();

			return conn;
		}

		internal void OpenPrivate (string address)
		{
			if (address == null)
				throw new ArgumentNullException ("address");

			AddressEntry[] entries = Address.Parse (address);
			if (entries.Length == 0)
				throw new Exception ("No addresses were found");

			//TODO: try alternative addresses if needed
			AddressEntry entry = entries[0];

			transport = Transport.Create (entry);

			//TODO: clean this bit up
			ns = transport.Stream;
		}

		void Authenticate ()
		{
			if (transport != null)
				transport.WriteCred ();

			SaslClient auth = new SaslClient (this);
			auth.Run ();
			isAuthenticated = true;
		}

		bool isAuthenticated = false;
		internal bool IsAuthenticated
		{
			get {
				return isAuthenticated;
			}
		}

		//Interlocked.Increment() handles the overflow condition for uint correctly, so it's ok to store the value as an int but cast it to uint
		int serial = 0;
		uint GenerateSerial ()
		{
			//return ++serial;
			return (uint)Interlocked.Increment (ref serial);
		}

		internal Message SendWithReplyAndBlock (Message msg)
		{
			PendingCall pending = SendWithReply (msg);
			return pending.Reply;
		}

		internal PendingCall SendWithReply (Message msg)
		{
			msg.ReplyExpected = true;
			msg.Header.Serial = GenerateSerial ();

			//TODO: throttle the maximum number of concurrent PendingCalls
			PendingCall pending = new PendingCall (this);
			pendingCalls[msg.Header.Serial] = pending;

			WriteMessage (msg);

			return pending;
		}

		internal uint Send (Message msg)
		{
			msg.Header.Serial = GenerateSerial ();

			WriteMessage (msg);

			//Outbound.Enqueue (msg);
			//temporary
			//Flush ();

			return msg.Header.Serial;
		}

		object writeLock = new object ();
		internal void WriteMessage (Message msg)
		{
			byte[] HeaderData = msg.GetHeaderData ();

			long msgLength = HeaderData.Length + (msg.Body != null ? msg.Body.Length : 0);
			if (msgLength > Protocol.MaxMessageLength)
				throw new Exception ("Message length " + msgLength + " exceeds maximum allowed " + Protocol.MaxMessageLength + " bytes");

			lock (writeLock) {
				ns.Write (HeaderData, 0, HeaderData.Length);
				if (msg.Body != null && msg.Body.Length != 0)
					ns.Write (msg.Body, 0, msg.Body.Length);
			}
		}

		Queue<Message> Inbound = new Queue<Message> ();
		/*
		Queue<Message> Outbound = new Queue<Message> ();

		public void Flush ()
		{
			//should just iterate the enumerator here
			while (Outbound.Count != 0) {
				Message msg = Outbound.Dequeue ();
				WriteMessage (msg);
			}
		}

		public bool ReadWrite (int timeout_milliseconds)
		{
			//TODO

			return true;
		}

		public bool ReadWrite ()
		{
			return ReadWrite (-1);
		}

		public bool Dispatch ()
		{
			//TODO
			Message msg = Inbound.Dequeue ();
			//HandleMessage (msg);

			return true;
		}

		public bool ReadWriteDispatch (int timeout_milliseconds)
		{
			//TODO
			return Dispatch ();
		}

		public bool ReadWriteDispatch ()
		{
			return ReadWriteDispatch (-1);
		}
		*/

		internal Message ReadMessage ()
		{
			byte[] header;
			byte[] body = null;

			int read;

			//16 bytes is the size of the fixed part of the header
			byte[] hbuf = new byte[16];
			read = ns.Read (hbuf, 0, 16);

			if (read == 0)
				return null;

			if (read != 16)
				throw new Exception ("Header read length mismatch: " + read + " of expected " + "16");

			EndianFlag endianness = (EndianFlag)hbuf[0];
			MessageReader reader = new MessageReader (endianness, hbuf);

			//discard the endian byte as we've already read it
			reader.ReadByte ();

			//discard message type and flags, which we don't care about here
			reader.ReadByte ();
			reader.ReadByte ();

			byte version = reader.ReadByte ();

			if (version < Protocol.MinVersion || version > Protocol.MaxVersion)
				throw new NotSupportedException ("Protocol version '" + version.ToString () + "' is not supported");

			if (Protocol.Verbose)
				if (version != Protocol.Version)
					Console.Error.WriteLine ("Warning: Protocol version '" + version.ToString () + "' is not explicitly supported but may be compatible");

			uint bodyLength = reader.ReadUInt32 ();
			//discard serial
			reader.ReadUInt32 ();
			uint headerLength = reader.ReadUInt32 ();

			//this check may become relevant if a future version of the protocol allows larger messages
			/*
			if (bodyLength > Int32.MaxValue || headerLength > Int32.MaxValue)
				throw new NotImplementedException ("Long messages are not yet supported");
			*/

			int bodyLen = (int)bodyLength;
			int toRead = (int)headerLength;

			//we fixup to include the padding following the header
			toRead = Protocol.Padded (toRead, 8);

			long msgLength = toRead + bodyLen;
			if (msgLength > Protocol.MaxMessageLength)
				throw new Exception ("Message length " + msgLength + " exceeds maximum allowed " + Protocol.MaxMessageLength + " bytes");

			header = new byte[16 + toRead];
			Array.Copy (hbuf, header, 16);

			read = ns.Read (header, 16, toRead);

			if (read != toRead)
				throw new Exception ("Message header length mismatch: " + read + " of expected " + toRead);

			//read the body
			if (bodyLen != 0) {
				body = new byte[bodyLen];
				read = ns.Read (body, 0, bodyLen);

				if (read != bodyLen)
					throw new Exception ("Message body length mismatch: " + read + " of expected " + bodyLen);
			}

			Message msg = new Message ();
			msg.Connection = this;
			msg.Body = body;
			msg.SetHeaderData (header);

			return msg;
		}

		//temporary hack
		internal void DispatchSignals ()
		{
			lock (Inbound) {
				while (Inbound.Count != 0) {
					Message msg = Inbound.Dequeue ();
					HandleSignal (msg);
				}
			}
		}

		internal Thread mainThread = Thread.CurrentThread;

		//temporary hack
		public void Iterate ()
		{
			mainThread = Thread.CurrentThread;

			//Message msg = Inbound.Dequeue ();
			Message msg = ReadMessage ();
			HandleMessage (msg);
			DispatchSignals ();
		}

		internal void HandleMessage (Message msg)
		{
			//TODO: support disconnection situations properly and move this check elsewhere
			if (msg == null)
				throw new ArgumentNullException ("msg", "Cannot handle a null message; maybe the bus was disconnected");

			{
				object field_value;
				if (msg.Header.Fields.TryGetValue (FieldCode.ReplySerial, out field_value)) {
					uint reply_serial = (uint)field_value;
					PendingCall pending;

					if (pendingCalls.TryGetValue (reply_serial, out pending)) {
						if (pendingCalls.Remove (reply_serial))
							pending.Reply = msg;

						return;
					}

					//we discard reply messages with no corresponding PendingCall
					if (Protocol.Verbose)
						Console.Error.WriteLine ("Unexpected reply message received: MessageType='" + msg.Header.MessageType + "', ReplySerial=" + reply_serial);

					return;
				}
			}

			switch (msg.Header.MessageType) {
				case MessageType.MethodCall:
					MethodCall method_call = new MethodCall (msg);
					HandleMethodCall (method_call);
					break;
				case MessageType.Signal:
					//HandleSignal (msg);
					lock (Inbound)
						Inbound.Enqueue (msg);
					break;
				case MessageType.Error:
					//TODO: better exception handling
					Error error = new Error (msg);
					string errMsg = String.Empty;
					if (msg.Signature.Value.StartsWith ("s")) {
						MessageReader reader = new MessageReader (msg);
						errMsg = reader.ReadString ();
					}
					//throw new Exception ("Remote Error: Signature='" + msg.Signature.Value + "' " + error.ErrorName + ": " + errMsg);
					//if (Protocol.Verbose)
					Console.Error.WriteLine ("Remote Error: Signature='" + msg.Signature.Value + "' " + error.ErrorName + ": " + errMsg);
					break;
				case MessageType.Invalid:
				default:
					throw new Exception ("Invalid message received: MessageType='" + msg.Header.MessageType + "'");
			}
		}

		Dictionary<uint,PendingCall> pendingCalls = new Dictionary<uint,PendingCall> ();

		//this might need reworking with MulticastDelegate
		internal void HandleSignal (Message msg)
		{
			Signal signal = new Signal (msg);

			//TODO: this is a hack, not necessary when MatchRule is complete
			MatchRule rule = new MatchRule ();
			rule.MessageType = MessageType.Signal;
			rule.Interface = signal.Interface;
			rule.Member = signal.Member;
			rule.Path = signal.Path;

			Delegate dlg;
			if (Handlers.TryGetValue (rule, out dlg)) {
				//dlg.DynamicInvoke (GetDynamicValues (msg));

				MethodInfo mi = dlg.Method;
				//signals have no return value
				dlg.DynamicInvoke (MessageHelper.GetDynamicValues (msg, mi.GetParameters ()));

			} else {
				//TODO: how should we handle this condition? sending an Error may not be appropriate in this case
				if (Protocol.Verbose)
					Console.Error.WriteLine ("Warning: No signal handler for " + signal.Member);
			}
		}

		internal Dictionary<MatchRule,Delegate> Handlers = new Dictionary<MatchRule,Delegate> ();

		//very messy
		internal void MaybeSendUnknownMethodError (MethodCall method_call)
		{
			Message msg = MessageHelper.CreateUnknownMethodError (method_call);
			if (msg != null)
				Send (msg);
		}

		//not particularly efficient and needs to be generalized
		internal void HandleMethodCall (MethodCall method_call)
		{
			//TODO: Ping and Introspect need to be abstracted and moved somewhere more appropriate once message filter infrastructure is complete

			//FIXME: these special cases are slightly broken for the case where the member but not the interface is specified in the message
			if (method_call.Interface == "org.freedesktop.DBus.Peer" && method_call.Member == "Ping") {
				Message reply = MessageHelper.ConstructReply (method_call);
				Send (reply);
				return;
			}

			if (method_call.Interface == "org.freedesktop.DBus.Introspectable" && method_call.Member == "Introspect") {
				Introspector intro = new Introspector ();
				intro.root_path = method_call.Path;
				intro.WriteStart ();

				//FIXME: do this properly
				//this is messy and inefficient
				List<string> linkNodes = new List<string> ();
				int depth = method_call.Path.Decomposed.Length;
				foreach (ObjectPath pth in RegisteredObjects.Keys) {
					if (pth.Value == (method_call.Path.Value)) {
						ExportObject exo = (ExportObject)RegisteredObjects[pth];
						intro.WriteType (exo.obj.GetType ());
					} else {
						for (ObjectPath cur = pth ; cur != null ; cur = cur.Parent) {
							if (cur.Value == method_call.Path.Value) {
								string linkNode = pth.Decomposed[depth];
								if (!linkNodes.Contains (linkNode)) {
									intro.WriteNode (linkNode);
									linkNodes.Add (linkNode);
								}
							}
						}
					}
				}

				intro.WriteEnd ();

				Message reply = MessageHelper.ConstructReply (method_call, intro.xml);
				Send (reply);
				return;
			}

			BusObject bo;
			if (RegisteredObjects.TryGetValue (method_call.Path, out bo)) {
				ExportObject eo = (ExportObject)bo;
				eo.HandleMethodCall (method_call);
			} else {
				MaybeSendUnknownMethodError (method_call);
			}
		}

		Dictionary<ObjectPath,BusObject> RegisteredObjects = new Dictionary<ObjectPath,BusObject> ();

		//FIXME: this shouldn't be part of the core API
		//that also applies to much of the other object mapping code

		public object GetObject (Type type, string bus_name, ObjectPath path)
		{
			//if (type == null)
			//	return GetObject (bus_name, path);

			//if the requested type is an interface, we can implement it efficiently
			//otherwise we fall back to using a transparent proxy
			if (type.IsInterface) {
				return BusObject.GetObject (this, bus_name, path, type);
			} else {
				if (Protocol.Verbose)
					Console.Error.WriteLine ("Warning: Note that MarshalByRefObject use is not recommended; for best performance, define interfaces");

				BusObject busObject = new BusObject (this, bus_name, path);
				DProxy prox = new DProxy (busObject, type);
				return prox.GetTransparentProxy ();
			}
		}

		public T GetObject<T> (string bus_name, ObjectPath path)
		{
			return (T)GetObject (typeof (T), bus_name, path);
		}

		[Obsolete ("Use the overload of Register() which does not take a bus_name parameter")]
		public void Register (string bus_name, ObjectPath path, object obj)
		{
			Register (path, obj);
		}

		[Obsolete ("Use the overload of Unregister() which does not take a bus_name parameter")]
		public object Unregister (string bus_name, ObjectPath path)
		{
			return Unregister (path);
		}

		public void Register (ObjectPath path, object obj)
		{
			ExportObject eo = new ExportObject (this, path, obj);
			eo.Registered = true;

			//TODO: implement some kind of tree data structure or internal object hierarchy. right now we are ignoring the name and putting all object paths in one namespace, which is bad
			RegisteredObjects[path] = eo;
		}

		public object Unregister (ObjectPath path)
		{
			BusObject bo;

			if (!RegisteredObjects.TryGetValue (path, out bo))
				throw new Exception ("Cannot unregister " + path + " as it isn't registered");

			RegisteredObjects.Remove (path);

			ExportObject eo = (ExportObject)bo;
			eo.Registered = false;

			return eo.obj;
		}

		//these look out of place, but are useful
		internal protected virtual void AddMatch (string rule)
		{
		}

		internal protected virtual void RemoveMatch (string rule)
		{
		}

		static Connection ()
		{
			if (BitConverter.IsLittleEndian)
				NativeEndianness = EndianFlag.Little;
			else
				NativeEndianness = EndianFlag.Big;
		}

		internal static readonly EndianFlag NativeEndianness;
	}
}

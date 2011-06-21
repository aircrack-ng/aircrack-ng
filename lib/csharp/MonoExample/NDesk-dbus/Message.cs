// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.IO;

namespace NDesk.DBus
{
	class Message
	{
		public Message ()
		{
			Header.Endianness = Connection.NativeEndianness;
			Header.MessageType = MessageType.MethodCall;
			Header.Flags = HeaderFlag.NoReplyExpected; //TODO: is this the right place to do this?
			Header.MajorVersion = Protocol.Version;
			Header.Fields = new Dictionary<FieldCode,object> ();
		}

		public Header Header;

		public Connection Connection;

		public Signature Signature
		{
			get {
				object o;
				if (Header.Fields.TryGetValue (FieldCode.Signature, out o))
					return (Signature)o;
				else
					return Signature.Empty;
			} set {
				if (value == Signature.Empty)
					Header.Fields.Remove (FieldCode.Signature);
				else
					Header.Fields[FieldCode.Signature] = value;
			}
		}

		public bool ReplyExpected
		{
			get {
				return (Header.Flags & HeaderFlag.NoReplyExpected) == HeaderFlag.None;
			} set {
				if (value)
					Header.Flags &= ~HeaderFlag.NoReplyExpected; //flag off
				else
					Header.Flags |= HeaderFlag.NoReplyExpected; //flag on
			}
		}

		//public HeaderField[] HeaderFields;
		//public Dictionary<FieldCode,object>;

		public byte[] Body;

		//TODO: make use of Locked
		/*
		protected bool locked = false;
		public bool Locked
		{
			get {
				return locked;
			}
		}
		*/

		public void SetHeaderData (byte[] data)
		{
			EndianFlag endianness = (EndianFlag)data[0];
			MessageReader reader = new MessageReader (endianness, data);

			Header = (Header)reader.ReadStruct (typeof (Header));
		}

		public byte[] GetHeaderData ()
		{
			if (Body != null)
				Header.Length = (uint)Body.Length;

			MessageWriter writer = new MessageWriter (Header.Endianness);
			writer.WriteValueType (Header, typeof (Header));
			writer.CloseWrite ();

			return writer.ToArray ();
		}
	}
}

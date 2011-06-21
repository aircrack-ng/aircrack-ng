// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.IO;

namespace NDesk.DBus
{
	//TODO: complete and use these wrapper classes
	//not sure exactly what I'm thinking but there seems to be sense here

	//FIXME: signature sending/receiving is currently ambiguous in this code
	//FIXME: in fact, these classes are totally broken and end up doing no-op, do not use without understanding the problem
	class MethodCall
	{
		public Message message = new Message ();

		public MethodCall (ObjectPath path, string @interface, string member, string destination, Signature signature)
		{
			message.Header.MessageType = MessageType.MethodCall;
			message.ReplyExpected = true;
			message.Header.Fields[FieldCode.Path] = path;
			if (@interface != null)
				message.Header.Fields[FieldCode.Interface] = @interface;
			message.Header.Fields[FieldCode.Member] = member;
			message.Header.Fields[FieldCode.Destination] = destination;
			//TODO: consider setting Sender here for p2p situations
			//this will allow us to remove the p2p hacks in MethodCall and Message
#if PROTO_REPLY_SIGNATURE
			//TODO
#endif
			//message.Header.Fields[FieldCode.Signature] = signature;
			//use the wrapper in Message because it checks for emptiness
			message.Signature = signature;
		}

		public MethodCall (Message message)
		{
			this.message = message;
			Path = (ObjectPath)message.Header.Fields[FieldCode.Path];
			if (message.Header.Fields.ContainsKey (FieldCode.Interface))
				Interface = (string)message.Header.Fields[FieldCode.Interface];
			Member = (string)message.Header.Fields[FieldCode.Member];
			Destination = (string)message.Header.Fields[FieldCode.Destination];
			//TODO: filled by the bus so reliable, but not the case for p2p
			//so we make it optional here, but this needs some more thought
			if (message.Header.Fields.ContainsKey (FieldCode.Sender))
				Sender = (string)message.Header.Fields[FieldCode.Sender];
#if PROTO_REPLY_SIGNATURE
			//TODO: note that an empty ReplySignature should really be treated differently to the field not existing!
			if (message.Header.Fields.ContainsKey (FieldCode.ReplySignature))
				ReplySignature = (Signature)message.Header.Fields[FieldCode.ReplySignature];
			else
				ReplySignature = Signature.Empty;
#endif
			//Signature = (Signature)message.Header.Fields[FieldCode.Signature];
			//use the wrapper in Message because it checks for emptiness
			Signature = message.Signature;
		}

		public ObjectPath Path;
		public string Interface;
		public string Member;
		public string Destination;
		public string Sender;
#if PROTO_REPLY_SIGNATURE
		public Signature ReplySignature;
#endif
		public Signature Signature;
	}

	class MethodReturn
	{
		public Message message = new Message ();

		public MethodReturn (uint reply_serial)
		{
			message.Header.MessageType = MessageType.MethodReturn;
			message.Header.Flags = HeaderFlag.NoReplyExpected | HeaderFlag.NoAutoStart;
			message.Header.Fields[FieldCode.ReplySerial] = reply_serial;
			//signature optional?
			//message.Header.Fields[FieldCode.Signature] = signature;
		}

		public MethodReturn (Message message)
		{
			this.message = message;
			ReplySerial = (uint)message.Header.Fields[FieldCode.ReplySerial];
		}

		public uint ReplySerial;
	}

	class Error
	{
		public Message message = new Message ();

		public Error (string error_name, uint reply_serial)
		{
			message.Header.MessageType = MessageType.Error;
			message.Header.Flags = HeaderFlag.NoReplyExpected | HeaderFlag.NoAutoStart;
			message.Header.Fields[FieldCode.ErrorName] = error_name;
			message.Header.Fields[FieldCode.ReplySerial] = reply_serial;
		}

		public Error (Message message)
		{
			this.message = message;
			ErrorName = (string)message.Header.Fields[FieldCode.ErrorName];
			ReplySerial = (uint)message.Header.Fields[FieldCode.ReplySerial];
			//Signature = (Signature)message.Header.Fields[FieldCode.Signature];
		}

		public string ErrorName;
		public uint ReplySerial;
		//public Signature Signature;
	}

	class Signal
	{
		public Message message = new Message ();

		public Signal (ObjectPath path, string @interface, string member)
		{
			message.Header.MessageType = MessageType.Signal;
			message.Header.Flags = HeaderFlag.NoReplyExpected | HeaderFlag.NoAutoStart;
			message.Header.Fields[FieldCode.Path] = path;
			message.Header.Fields[FieldCode.Interface] = @interface;
			message.Header.Fields[FieldCode.Member] = member;
		}

		public Signal (Message message)
		{
			this.message = message;
			Path = (ObjectPath)message.Header.Fields[FieldCode.Path];
			Interface = (string)message.Header.Fields[FieldCode.Interface];
			Member = (string)message.Header.Fields[FieldCode.Member];
			if (message.Header.Fields.ContainsKey (FieldCode.Sender))
				Sender = (string)message.Header.Fields[FieldCode.Sender];
		}

		public ObjectPath Path;
		public string Interface;
		public string Member;
		public string Sender;
	}
}

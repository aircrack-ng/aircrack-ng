// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;

namespace NDesk.DBus
{
	class MessageFilter
	{
		//this should probably be made to use HeaderField or similar
		//this class is not generalized yet

		public static string MessageTypeToString (MessageType mtype)
		{
			switch (mtype)
			{
				case MessageType.MethodCall:
					return "method_call";
				case MessageType.MethodReturn:
					return "method_return";
				case MessageType.Error:
					return "error";
				case MessageType.Signal:
					return "signal";
				case MessageType.Invalid:
					return "invalid";
				default:
					throw new Exception ("Bad MessageType: " + mtype);
			}
		}

		public static MessageType StringToMessageType (string text)
		{
			switch (text)
			{
				case "method_call":
					return MessageType.MethodCall;
				case "method_return":
					return MessageType.MethodReturn;
				case "error":
					return MessageType.Error;
				case "signal":
					return MessageType.Signal;
				case "invalid":
					return MessageType.Invalid;
				default:
					throw new Exception ("Bad MessageType: " + text);
			}
		}

		//TODO: remove this -- left here for the benefit of the monitor tool for now
		public static string CreateMatchRule (MessageType mtype)
		{
			return "type='" + MessageTypeToString (mtype) + "'";
		}
	}
}

// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.Reflection;

namespace NDesk.DBus
{
	static class Mapper
	{
		//TODO: move these Get*Name helpers somewhere more appropriate
		public static string GetArgumentName (ParameterInfo pi)
		{
			string argName = pi.Name;

			if (pi.IsRetval && String.IsNullOrEmpty (argName))
				argName = "ret";

			return GetArgumentName ((ICustomAttributeProvider)pi, argName);
		}

		public static string GetArgumentName (ICustomAttributeProvider attrProvider, string defaultName)
		{
			string argName = defaultName;

			//TODO: no need for foreach
			foreach (ArgumentAttribute aa in attrProvider.GetCustomAttributes (typeof (ArgumentAttribute), true))
				argName = aa.Name;

			return argName;
		}

		//TODO: these two methods are quite messy and need review
		public static IEnumerable<MemberInfo> GetPublicMembers (Type type)
		{
			//note that Type.GetInterfaces() returns all interfaces with flattened hierarchy
			foreach (Type ifType in type.GetInterfaces ())
				foreach (MemberInfo mi in GetDeclaredPublicMembers (ifType))
					yield return mi;

			if (IsPublic (type))
				foreach (MemberInfo mi in GetDeclaredPublicMembers (type))
					yield return mi;
		}

		static IEnumerable<MemberInfo> GetDeclaredPublicMembers (Type type)
		{
			if (IsPublic (type))
				foreach (MemberInfo mi in type.GetMembers (BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
					yield return mi;
		}

		//this method walks the interface tree in an undefined manner and returns the first match, or if no matches are found, null
		//the logic needs review and cleanup
		//TODO: unify member name mapping as is already done with interfaces and args
		public static MethodInfo GetMethod (Type type, MethodCall method_call)
		{
			foreach (MemberInfo member in Mapper.GetPublicMembers (type)) {
				//this could be made more efficient by using the given interface name earlier and avoiding walking through all public interfaces
				if (method_call.Interface != null)
					if (GetInterfaceName (member) != method_call.Interface)
						continue;

				MethodInfo meth = null;
				Type[] inTypes = null;

				if (member is PropertyInfo) {
					PropertyInfo prop = member as PropertyInfo;

					MethodInfo getter = prop.GetGetMethod (false);
					MethodInfo setter = prop.GetSetMethod (false);

					if (getter != null && "Get" + prop.Name == method_call.Member) {
						meth = getter;
						inTypes = Type.EmptyTypes;
					} else if (setter != null && "Set" + prop.Name == method_call.Member) {
						meth = setter;
						inTypes = new Type[] {prop.PropertyType};
					}
				} else {
					meth = member as MethodInfo;

					if (meth == null)
						continue;

					if (meth.Name != method_call.Member)
						continue;

					inTypes = Mapper.GetTypes (ArgDirection.In, meth.GetParameters ());
				}

				if (meth == null || inTypes == null)
					continue;

				Signature inSig = Signature.GetSig (inTypes);

				if (inSig != method_call.Signature)
					continue;

				return meth;
			}

			return null;
		}

		public static bool IsPublic (MemberInfo mi)
		{
			return IsPublic (mi.DeclaringType);
		}

		public static bool IsPublic (Type type)
		{
			//we need to have a proper look at what's really public at some point
			//this will do for now

			if (type.IsDefined (typeof (InterfaceAttribute), false))
				return true;

			if (type.IsSubclassOf (typeof (MarshalByRefObject)))
				return true;

			return false;
		}

		public static string GetInterfaceName (MemberInfo mi)
		{
			return GetInterfaceName (mi.DeclaringType);
		}

		public static string GetInterfaceName (Type type)
		{
			string interfaceName = type.FullName;

			//TODO: better fallbacks and namespace mangling when no InterfaceAttribute is available

			//TODO: no need for foreach
			foreach (InterfaceAttribute ia in type.GetCustomAttributes (typeof (InterfaceAttribute), true))
				interfaceName = ia.Name;

			return interfaceName;
		}

		public static Type[] GetTypes (ArgDirection dir, ParameterInfo[] parms)
		{
			List<Type> types = new List<Type> ();

			//TODO: consider InOut/Ref

			for (int i = 0 ; i != parms.Length ; i++) {
				switch (dir) {
					case ArgDirection.In:
						//docs say IsIn isn't reliable, and this is indeed true
						//if (parms[i].IsIn)
						if (!parms[i].IsOut)
							types.Add (parms[i].ParameterType);
						break;
					case ArgDirection.Out:
						if (parms[i].IsOut) {
							//TODO: note that IsOut is optional to the compiler, we may want to use IsByRef instead
						//eg: if (parms[i].ParameterType.IsByRef)
							types.Add (parms[i].ParameterType.GetElementType ());
						}
						break;
				}
			}

			return types.ToArray ();
		}

		public static bool IsDeprecated (ICustomAttributeProvider attrProvider)
		{
			return attrProvider.IsDefined (typeof (ObsoleteAttribute), true);
		}

		static bool AreEqual (Type[] a, Type[] b)
		{
			if (a.Length != b.Length)
				return false;

			for (int i = 0 ; i != a.Length ; i++)
				if (a[i] != b[i])
					return false;

			return true;
		}

		//workaround for Mono bug #81035 (memory leak)
		static List<Type> genTypes = new List<Type> ();
		internal static Type GetGenericType (Type defType, Type[] parms)
		{
			foreach (Type genType in genTypes) {
				if (genType.GetGenericTypeDefinition () != defType)
					continue;

				Type[] genParms = genType.GetGenericArguments ();

				if (!AreEqual (genParms, parms))
					continue;

				return genType;
			}

			Type type = defType.MakeGenericType (parms);
			genTypes.Add (type);
			return type;
		}
	}

	//TODO: this class is messy, move the methods somewhere more appropriate
	static class MessageHelper
	{
		public static Message CreateUnknownMethodError (MethodCall method_call)
		{
			if (!method_call.message.ReplyExpected)
				return null;

			string errMsg = String.Format ("Method \"{0}\" with signature \"{1}\" on interface \"{2}\" doesn't exist", method_call.Member, method_call.Signature.Value, method_call.Interface);

			Error error = new Error ("org.freedesktop.DBus.Error.UnknownMethod", method_call.message.Header.Serial);
			error.message.Signature = new Signature (DType.String);

			MessageWriter writer = new MessageWriter (Connection.NativeEndianness);
			writer.Write (errMsg);
			error.message.Body = writer.ToArray ();

			//TODO: we should be more strict here, but this fallback was added as a quick fix for p2p
			if (method_call.Sender != null)
				error.message.Header.Fields[FieldCode.Destination] = method_call.Sender;

			return error.message;
		}

		public static void WriteDynamicValues (MessageWriter mw, ParameterInfo[] parms, object[] vals)
		{
			foreach (ParameterInfo parm in parms) {
				if (!parm.IsOut)
					continue;

				Type actualType = parm.ParameterType.GetElementType ();
				mw.Write (actualType, vals[parm.Position]);
			}
		}

		public static object[] GetDynamicValues (Message msg, ParameterInfo[] parms)
		{
			//TODO: this validation check should provide better information, eg. message dump or a stack trace, or at least the interface/member
			/*
			if (Protocol.Verbose) {
				Signature expected = Signature.GetSig (types);
				Signature actual = msg.Signature;
				if (actual != expected)
					Console.Error.WriteLine ("Warning: The signature of the message does not match that of the handler: " + "Expected '" + expected + "', got '" + actual + "'");
			}
			*/

			object[] vals = new object[parms.Length];

			if (msg.Body != null) {
				MessageReader reader = new MessageReader (msg);
				foreach (ParameterInfo parm in parms) {
					if (parm.IsOut)
						continue;

					vals[parm.Position] = reader.ReadValue (parm.ParameterType);
				}
			}

			return vals;
		}

		public static object[] GetDynamicValues (Message msg, Type[] types)
		{
			//TODO: this validation check should provide better information, eg. message dump or a stack trace, or at least the interface/member
			if (Protocol.Verbose) {
				Signature expected = Signature.GetSig (types);
				Signature actual = msg.Signature;
				if (actual != expected)
					Console.Error.WriteLine ("Warning: The signature of the message does not match that of the handler: " + "Expected '" + expected + "', got '" + actual + "'");
			}

			object[] vals = new object[types.Length];

			if (msg.Body != null) {
				MessageReader reader = new MessageReader (msg);

				for (int i = 0 ; i != types.Length ; i++)
					vals[i] = reader.ReadValue (types[i]);
			}

			return vals;
		}

		public static Message ConstructReply (MethodCall method_call, params object[] vals)
		{
			MethodReturn method_return = new MethodReturn (method_call.message.Header.Serial);
			Message replyMsg = method_return.message;

			Signature inSig = Signature.GetSig (vals);

			if (vals != null && vals.Length != 0) {
				MessageWriter writer = new MessageWriter (Connection.NativeEndianness);

				foreach (object arg in vals)
					writer.Write (arg.GetType (), arg);

				replyMsg.Body = writer.ToArray ();
			}

			//TODO: we should be more strict here, but this fallback was added as a quick fix for p2p
			if (method_call.Sender != null)
				replyMsg.Header.Fields[FieldCode.Destination] = method_call.Sender;

			replyMsg.Signature = inSig;

			//replyMsg.WriteHeader ();

			return replyMsg;
		}

		public static Message ConstructDynamicReply (MethodCall method_call, MethodInfo mi, object retVal, object[] vals)
		{
			Type retType = mi.ReturnType;

			MethodReturn method_return = new MethodReturn (method_call.message.Header.Serial);
			Message replyMsg = method_return.message;

			Signature outSig = Signature.GetSig (retType);
			outSig += Signature.GetSig (Mapper.GetTypes (ArgDirection.Out, mi.GetParameters ()));

			if (outSig != Signature.Empty) {
				MessageWriter writer = new MessageWriter (Connection.NativeEndianness);

				//first write the return value, if any
				if (retType != null && retType != typeof (void))
					writer.Write (retType, retVal);

				//then write the out args
				WriteDynamicValues (writer, mi.GetParameters (), vals);

				replyMsg.Body = writer.ToArray ();
			}

			//TODO: we should be more strict here, but this fallback was added as a quick fix for p2p
			if (method_call.Sender != null)
				replyMsg.Header.Fields[FieldCode.Destination] = method_call.Sender;

			replyMsg.Signature = outSig;

			return replyMsg;
		}
	}

	[AttributeUsage (AttributeTargets.Interface | AttributeTargets.Class, AllowMultiple=false, Inherited=true)]
	public class InterfaceAttribute : Attribute
	{
		public string Name;

		public InterfaceAttribute (string name)
		{
			this.Name = name;
		}
	}

	[AttributeUsage (AttributeTargets.Parameter | AttributeTargets.ReturnValue, AllowMultiple=false, Inherited=true)]
	public class ArgumentAttribute : Attribute
	{
		public string Name;

		public ArgumentAttribute (string name)
		{
			this.Name = name;
		}
	}
}

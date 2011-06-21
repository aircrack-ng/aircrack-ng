// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Text;
using System.Reflection;

namespace NDesk.DBus
{
	//TODO: complete this class
	class Introspector
	{
		const string NAMESPACE = "http://www.freedesktop.org/standards/dbus";
		const string PUBLIC_IDENTIFIER = "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN";
		const string SYSTEM_IDENTIFIER = "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd";

		public StringBuilder sb;
		public string xml;
		public ObjectPath root_path = ObjectPath.Root;

		protected XmlWriter writer;

		public Introspector ()
		{
			XmlWriterSettings settings = new XmlWriterSettings ();
			settings.Indent = true;
			settings.IndentChars = ("  ");
			settings.OmitXmlDeclaration = true;

			sb = new StringBuilder ();

			writer = XmlWriter.Create (sb, settings);
		}

		static string GetProductDescription ()
		{
			String version;

			Assembly assembly = Assembly.GetExecutingAssembly ();
			AssemblyName aname = assembly.GetName ();

			AssemblyInformationalVersionAttribute iversion = Attribute.GetCustomAttribute (assembly, typeof (AssemblyInformationalVersionAttribute)) as AssemblyInformationalVersionAttribute;

			if (iversion != null)
				version = iversion.InformationalVersion;
			else
				version = aname.Version.ToString ();

			return aname.Name + " " + version;
		}

		public void WriteStart ()
		{
			writer.WriteDocType ("node", PUBLIC_IDENTIFIER, SYSTEM_IDENTIFIER, null);

			writer.WriteComment (" " + GetProductDescription () + " ");

			//the root node element
			writer.WriteStartElement ("node");
		}

		public void WriteNode (string name)
		{
			writer.WriteStartElement ("node");
			writer.WriteAttributeString ("name", name);
			writer.WriteEndElement ();
		}

		public void WriteEnd ()
		{
			/*
			WriteEnum (typeof (org.freedesktop.DBus.NameFlag));
			WriteEnum (typeof (org.freedesktop.DBus.NameReply));
			WriteEnum (typeof (org.freedesktop.DBus.ReleaseNameReply));
			WriteEnum (typeof (org.freedesktop.DBus.StartReply));
			WriteInterface (typeof (org.freedesktop.DBus.IBus));
			*/

			writer.WriteEndElement ();

			writer.Flush ();
			xml = sb.ToString ();
		}

		//public void WriteNode ()
		public void WriteType (Type target_type)
		{
			//writer.WriteStartElement ("node");

			//TODO: non-well-known introspection has paths as well, which we don't do yet. read the spec again
			//hackishly just remove the root '/' to make the path relative for now
			//writer.WriteAttributeString ("name", target_path.Value.Substring (1));
			//writer.WriteAttributeString ("name", "test");

			//reflect our own interface manually
			WriteInterface (typeof (org.freedesktop.DBus.Introspectable));

			//reflect the target interface
			if (target_type != null) {
				WriteInterface (target_type);

				foreach (Type ifType in target_type.GetInterfaces ())
					WriteInterface (ifType);
			}

			//TODO: review recursion of interfaces and inheritance hierarchy

			//writer.WriteEndElement ();
		}

		public void WriteArg (ParameterInfo pi)
		{
			WriteArg (pi.ParameterType, Mapper.GetArgumentName (pi), pi.IsOut, false);
		}

		public void WriteArgReverse (ParameterInfo pi)
		{
			WriteArg (pi.ParameterType, Mapper.GetArgumentName (pi), pi.IsOut, true);
		}

		//TODO: clean up and get rid of reverse (or argIsOut) parm
		public void WriteArg (Type argType, string argName, bool argIsOut, bool reverse)
		{
			argType = argIsOut ? argType.GetElementType () : argType;
			if (argType == typeof (void))
				return;

			writer.WriteStartElement ("arg");

			if (!String.IsNullOrEmpty (argName))
				writer.WriteAttributeString ("name", argName);

			//we can't rely on the default direction (qt-dbus requires a direction at time of writing), so we use a boolean to reverse the parameter direction and make it explicit

			if (argIsOut)
				writer.WriteAttributeString ("direction", !reverse ? "out" : "in");
			else
				writer.WriteAttributeString ("direction", !reverse ? "in" : "out");

			Signature sig = Signature.GetSig (argType);

			//TODO: avoid writing null (DType.Invalid) to the XML stream
			writer.WriteAttributeString ("type", sig.Value);

			//annotations aren't valid in an arg element, so this is disabled
			//if (argType.IsEnum)
			//	WriteAnnotation ("org.ndesk.DBus.Enum", Mapper.GetInterfaceName (argType));

			writer.WriteEndElement ();
		}

		public void WriteMethod (MethodInfo mi)
		{
			writer.WriteStartElement ("method");
			writer.WriteAttributeString ("name", mi.Name);

			foreach (ParameterInfo pi in mi.GetParameters ())
				WriteArg (pi);

			//Mono <= 1.1.13 doesn't support MethodInfo.ReturnParameter, so avoid it
			//WriteArgReverse (mi.ReturnParameter);
			WriteArg (mi.ReturnType, Mapper.GetArgumentName (mi.ReturnTypeCustomAttributes, "ret"), false, true);

			WriteAnnotations (mi);

			writer.WriteEndElement ();
		}

		public void WriteProperty (PropertyInfo pri)
		{
			//expose properties as dbus properties
			writer.WriteStartElement ("property");
			writer.WriteAttributeString ("name", pri.Name);
			writer.WriteAttributeString ("type", Signature.GetSig (pri.PropertyType).Value);
			string access = (pri.CanRead ? "read" : String.Empty) + (pri.CanWrite ? "write" : String.Empty);
			writer.WriteAttributeString ("access", access);
			WriteAnnotations (pri);
			writer.WriteEndElement ();

			//expose properties as methods also
			//it may not be worth doing this in the long run
			/*
			if (pri.CanRead) {
				writer.WriteStartElement ("method");
				writer.WriteAttributeString ("name", "Get" + pri.Name);
				WriteArgReverse (pri.GetGetMethod ().ReturnParameter);
				writer.WriteEndElement ();
			}

			if (pri.CanWrite) {
				writer.WriteStartElement ("method");
				writer.WriteAttributeString ("name", "Set" + pri.Name);
				foreach (ParameterInfo pi in pri.GetSetMethod ().GetParameters ())
					WriteArg (pi);
				writer.WriteEndElement ();
			}
			*/
		}

		public void WriteSignal (EventInfo ei)
		{
			writer.WriteStartElement ("signal");
			writer.WriteAttributeString ("name", ei.Name);

			foreach (ParameterInfo pi in ei.EventHandlerType.GetMethod ("Invoke").GetParameters ())
				WriteArgReverse (pi);

			WriteAnnotations (ei);

			//no need to consider the delegate return value as dbus doesn't support it
			writer.WriteEndElement ();
		}

		const BindingFlags relevantBindingFlags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly;

		public void WriteInterface (Type type)
		{
			if (type == null)
				return;

			//TODO: this is unreliable, fix it
			if (!Mapper.IsPublic (type))
				return;

			writer.WriteStartElement ("interface");

			writer.WriteAttributeString ("name", Mapper.GetInterfaceName (type));

			/*
			foreach (MemberInfo mbi in type.GetMembers (relevantBindingFlags)) {
				switch (mbi.MemberType) {
					case MemberTypes.Method:
						if (!((MethodInfo)mbi).IsSpecialName)
							WriteMethod ((MethodInfo)mbi);
						break;
					case MemberTypes.Event:
						WriteSignal ((EventInfo)mbi);
						break;
					case MemberTypes.Property:
						WriteProperty ((PropertyInfo)mbi);
						break;
					default:
						Console.Error.WriteLine ("Warning: Unhandled MemberType '{0}' encountered while introspecting {1}", mbi.MemberType, type.FullName);
						break;
				}
			}
			*/

			foreach (MethodInfo mi in type.GetMethods (relevantBindingFlags))
				if (!mi.IsSpecialName)
					WriteMethod (mi);

			foreach (EventInfo ei in type.GetEvents (relevantBindingFlags))
				WriteSignal (ei);

			foreach (PropertyInfo pri in type.GetProperties (relevantBindingFlags))
				WriteProperty (pri);

			//TODO: indexers

			//TODO: attributes as annotations?

			writer.WriteEndElement ();

			//this recursion seems somewhat inelegant
			WriteInterface (type.BaseType);
		}

		public void WriteAnnotations (ICustomAttributeProvider attrProvider)
		{
			if (Mapper.IsDeprecated (attrProvider))
				WriteAnnotation ("org.freedesktop.DBus.Deprecated", "true");
		}

		public void WriteAnnotation (string name, string value)
		{
			writer.WriteStartElement ("annotation");

			writer.WriteAttributeString ("name", name);
			writer.WriteAttributeString ("value", value);

			writer.WriteEndElement ();
		}

		//this is not in the spec, and is not finalized
		public void WriteEnum (Type type)
		{
			writer.WriteStartElement ("enum");
			writer.WriteAttributeString ("name", Mapper.GetInterfaceName (type));
			writer.WriteAttributeString ("type", Signature.GetSig (type.GetElementType ()).Value);
			writer.WriteAttributeString ("flags", (type.IsDefined (typeof (FlagsAttribute), false)) ? "true" : "false");

			string[] names = Enum.GetNames (type);

			int i = 0;
			foreach (Enum val in Enum.GetValues (type)) {
				writer.WriteStartElement ("element");
				writer.WriteAttributeString ("name", names[i++]);
				writer.WriteAttributeString ("value", val.ToString ("d"));
				writer.WriteEndElement ();
			}

			writer.WriteEndElement ();
		}
	}
}

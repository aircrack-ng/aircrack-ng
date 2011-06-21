// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace NDesk.DBus
{
	class MessageWriter
	{
		protected EndianFlag endianness;
		protected MemoryStream stream;

		public Connection connection;

		//a default constructor is a bad idea for now as we want to make sure the header and content-type match
		public MessageWriter () : this (Connection.NativeEndianness) {}

		public MessageWriter (EndianFlag endianness)
		{
			this.endianness = endianness;
			stream = new MemoryStream ();
		}

		public byte[] ToArray ()
		{
			//TODO: mark the writer locked or something here
			return stream.ToArray ();
		}

		public void CloseWrite ()
		{
			int needed = Protocol.PadNeeded ((int)stream.Position, 8);
			for (int i = 0 ; i != needed ; i++)
				stream.WriteByte (0);
		}

		public void Write (byte val)
		{
			stream.WriteByte (val);
		}

		public void Write (bool val)
		{
			Write ((uint) (val ? 1 : 0));
		}

		unsafe protected void MarshalUShort (byte *data)
		{
			WritePad (2);
			byte[] dst = new byte[2];

			if (endianness == Connection.NativeEndianness) {
				dst[0] = data[0];
				dst[1] = data[1];
			} else {
				dst[0] = data[1];
				dst[1] = data[0];
			}

			stream.Write (dst, 0, 2);
		}

		unsafe public void Write (short val)
		{
			MarshalUShort ((byte*)&val);
		}

		unsafe public void Write (ushort val)
		{
			MarshalUShort ((byte*)&val);
		}

		unsafe protected void MarshalUInt (byte *data)
		{
			WritePad (4);
			byte[] dst = new byte[4];

			if (endianness == Connection.NativeEndianness) {
				dst[0] = data[0];
				dst[1] = data[1];
				dst[2] = data[2];
				dst[3] = data[3];
			} else {
				dst[0] = data[3];
				dst[1] = data[2];
				dst[2] = data[1];
				dst[3] = data[0];
			}

			stream.Write (dst, 0, 4);
		}

		unsafe public void Write (int val)
		{
			MarshalUInt ((byte*)&val);
		}

		unsafe public void Write (uint val)
		{
			MarshalUInt ((byte*)&val);
		}

		unsafe protected void MarshalULong (byte *data)
		{
			WritePad (8);
			byte[] dst = new byte[8];

			if (endianness == Connection.NativeEndianness) {
				for (int i = 0; i < 8; ++i)
					dst[i] = data[i];
			} else {
				for (int i = 0; i < 8; ++i)
					dst[i] = data[7 - i];
			}

			stream.Write (dst, 0, 8);
		}

		unsafe public void Write (long val)
		{
			MarshalULong ((byte*)&val);
		}

		unsafe public void Write (ulong val)
		{
			MarshalULong ((byte*)&val);
		}

#if !DISABLE_SINGLE
		unsafe public void Write (float val)
		{
			MarshalUInt ((byte*)&val);
		}
#endif

		unsafe public void Write (double val)
		{
			MarshalULong ((byte*)&val);
		}

		public void Write (string val)
		{
			byte[] utf8_data = Encoding.UTF8.GetBytes (val);
			Write ((uint)utf8_data.Length);
			stream.Write (utf8_data, 0, utf8_data.Length);
			WriteNull ();
		}

		public void Write (ObjectPath val)
		{
			Write (val.Value);
		}

		public void Write (Signature val)
		{
			byte[] ascii_data = val.GetBuffer ();

			if (ascii_data.Length > Protocol.MaxSignatureLength)
				throw new Exception ("Signature length " + ascii_data.Length + " exceeds maximum allowed " + Protocol.MaxSignatureLength + " bytes");

			Write ((byte)ascii_data.Length);
			stream.Write (ascii_data, 0, ascii_data.Length);
			WriteNull ();
		}

		public void WriteComplex (object val, Type type)
		{
			if (type == typeof (void))
				return;

			if (type.IsArray) {
				WriteArray (val, type.GetElementType ());
			} else if (type.IsGenericType && (type.GetGenericTypeDefinition () == typeof (IDictionary<,>) || type.GetGenericTypeDefinition () == typeof (Dictionary<,>))) {
				Type[] genArgs = type.GetGenericArguments ();
				System.Collections.IDictionary idict = (System.Collections.IDictionary)val;
				WriteFromDict (genArgs[0], genArgs[1], idict);
			} else if (Mapper.IsPublic (type)) {
				WriteObject (type, val);
			} else if (!type.IsPrimitive && !type.IsEnum) {
				WriteValueType (val, type);
				/*
			} else if (type.IsGenericType && type.GetGenericTypeDefinition () == typeof (Nullable<>)) {
				//is it possible to support nullable types?
				Type[] genArgs = type.GetGenericArguments ();
				WriteVariant (genArgs[0], val);
				*/
			} else {
				throw new Exception ("Can't write");
			}
		}

		public void Write (Type type, object val)
		{
			if (type == typeof (void))
				return;

			if (type.IsArray) {
				WriteArray (val, type.GetElementType ());
			} else if (type == typeof (ObjectPath)) {
				Write ((ObjectPath)val);
			} else if (type == typeof (Signature)) {
				Write ((Signature)val);
			} else if (type == typeof (object)) {
				Write (val);
			} else if (type == typeof (string)) {
				Write ((string)val);
			} else if (type.IsGenericType && (type.GetGenericTypeDefinition () == typeof (IDictionary<,>) || type.GetGenericTypeDefinition () == typeof (Dictionary<,>))) {
				Type[] genArgs = type.GetGenericArguments ();
				System.Collections.IDictionary idict = (System.Collections.IDictionary)val;
				WriteFromDict (genArgs[0], genArgs[1], idict);
			} else if (Mapper.IsPublic (type)) {
				WriteObject (type, val);
			} else if (!type.IsPrimitive && !type.IsEnum) {
				WriteValueType (val, type);
			} else {
				Write (Signature.TypeToDType (type), val);
			}
		}

		//helper method, should not be used as it boxes needlessly
		public void Write (DType dtype, object val)
		{
			switch (dtype)
			{
				case DType.Byte:
				{
					Write ((byte)val);
				}
				break;
				case DType.Boolean:
				{
					Write ((bool)val);
				}
				break;
				case DType.Int16:
				{
					Write ((short)val);
				}
				break;
				case DType.UInt16:
				{
					Write ((ushort)val);
				}
				break;
				case DType.Int32:
				{
					Write ((int)val);
				}
				break;
				case DType.UInt32:
				{
					Write ((uint)val);
				}
				break;
				case DType.Int64:
				{
					Write ((long)val);
				}
				break;
				case DType.UInt64:
				{
					Write ((ulong)val);
				}
				break;
#if !DISABLE_SINGLE
				case DType.Single:
				{
					Write ((float)val);
				}
				break;
#endif
				case DType.Double:
				{
					Write ((double)val);
				}
				break;
				case DType.String:
				{
					Write ((string)val);
				}
				break;
				case DType.ObjectPath:
				{
					Write ((ObjectPath)val);
				}
				break;
				case DType.Signature:
				{
					Write ((Signature)val);
				}
				break;
				case DType.Variant:
				{
					Write ((object)val);
				}
				break;
				default:
				throw new Exception ("Unhandled D-Bus type: " + dtype);
			}
		}

		public void WriteObject (Type type, object val)
		{
			ObjectPath path;

			BusObject bobj = val as BusObject;

			if (bobj == null && val is MarshalByRefObject) {
				bobj = ((MarshalByRefObject)val).GetLifetimeService () as BusObject;
			}

			if (bobj == null)
				throw new Exception ("No object reference to write");

			path = bobj.Path;

			Write (path);
		}

		//variant
		public void Write (object val)
		{
			//TODO: maybe support sending null variants

			if (val == null)
				throw new NotSupportedException ("Cannot send null variant");

			Type type = val.GetType ();

			WriteVariant (type, val);
		}

		public void WriteVariant (Type type, object val)
		{
			Signature sig = Signature.GetSig (type);

			Write (sig);
			Write (type, val);
		}

		//this requires a seekable stream for now
		public void WriteArray (object obj, Type elemType)
		{
			Array val = (Array)obj;

			//TODO: more fast paths for primitive arrays
			if (elemType == typeof (byte)) {
				if (val.Length > Protocol.MaxArrayLength)
					throw new Exception ("Array length " + val.Length + " exceeds maximum allowed " + Protocol.MaxArrayLength + " bytes");

				Write ((uint)val.Length);
				stream.Write ((byte[])val, 0, val.Length);
				return;
			}

			long origPos = stream.Position;
			Write ((uint)0);

			//advance to the alignment of the element
			WritePad (Protocol.GetAlignment (Signature.TypeToDType (elemType)));

			long startPos = stream.Position;

			foreach (object elem in val)
				Write (elemType, elem);

			long endPos = stream.Position;
			uint ln = (uint)(endPos - startPos);
			stream.Position = origPos;

			if (ln > Protocol.MaxArrayLength)
				throw new Exception ("Array length " + ln + " exceeds maximum allowed " + Protocol.MaxArrayLength + " bytes");

			Write (ln);
			stream.Position = endPos;
		}

		public void WriteFromDict (Type keyType, Type valType, System.Collections.IDictionary val)
		{
			long origPos = stream.Position;
			Write ((uint)0);

			//advance to the alignment of the element
			//WritePad (Protocol.GetAlignment (Signature.TypeToDType (type)));
			WritePad (8);

			long startPos = stream.Position;

			foreach (System.Collections.DictionaryEntry entry in val)
			{
				WritePad (8);

				Write (keyType, entry.Key);
				Write (valType, entry.Value);
			}

			long endPos = stream.Position;
			uint ln = (uint)(endPos - startPos);
			stream.Position = origPos;

			if (ln > Protocol.MaxArrayLength)
				throw new Exception ("Dict length " + ln + " exceeds maximum allowed " + Protocol.MaxArrayLength + " bytes");

			Write (ln);
			stream.Position = endPos;
		}

		public void WriteValueType (object val, Type type)
		{
			MethodInfo mi = TypeImplementer.GetWriteMethod (type);
			mi.Invoke (null, new object[] {this, val});
		}

		/*
		public void WriteValueTypeOld (object val, Type type)
		{
			WritePad (8);

			if (type.IsGenericType && type.GetGenericTypeDefinition () == typeof (KeyValuePair<,>)) {
				System.Reflection.PropertyInfo key_prop = type.GetProperty ("Key");
				Write (key_prop.PropertyType, key_prop.GetValue (val, null));

				System.Reflection.PropertyInfo val_prop = type.GetProperty ("Value");
				Write (val_prop.PropertyType, val_prop.GetValue (val, null));

				return;
			}

			FieldInfo[] fis = type.GetFields (BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

			foreach (System.Reflection.FieldInfo fi in fis) {
				object elem;
				elem = fi.GetValue (val);
				Write (fi.FieldType, elem);
			}
		}
		*/

		public void WriteNull ()
		{
			stream.WriteByte (0);
		}

		public void WritePad (int alignment)
		{
			stream.Position = Protocol.Padded ((int)stream.Position, alignment);
		}
	}
}

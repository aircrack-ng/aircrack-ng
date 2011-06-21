// Copyright 2007 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Reflection;
using System.Reflection.Emit;
using System.Collections.Generic;

namespace NDesk.DBus
{
	static class TypeImplementer
	{
		static AssemblyBuilder asmB;
		static ModuleBuilder modB;

		static void InitHack ()
		{
			if (asmB != null)
				return;

			asmB = AppDomain.CurrentDomain.DefineDynamicAssembly (new AssemblyName ("NDesk.DBus.Proxies"), AssemblyBuilderAccess.Run);
			modB = asmB.DefineDynamicModule ("ProxyModule");
		}

		static Dictionary<Type,Type> map = new Dictionary<Type,Type> ();

		public static Type GetImplementation (Type declType)
		{
			Type retT;

			if (map.TryGetValue (declType, out retT))
				return retT;

			InitHack ();

			TypeBuilder typeB = modB.DefineType (declType.Name + "Proxy", TypeAttributes.Class | TypeAttributes.Public, typeof (BusObject));

			Implement (typeB, declType);

			foreach (Type iface in declType.GetInterfaces ())
				Implement (typeB, iface);

			retT = typeB.CreateType ();
			map[declType] = retT;

			return retT;
		}

		public static void Implement (TypeBuilder typeB, Type iface)
		{
			typeB.AddInterfaceImplementation (iface);

			foreach (MethodInfo declMethod in iface.GetMethods ()) {
				ParameterInfo[] parms = declMethod.GetParameters ();

				Type[] parmTypes = new Type[parms.Length];
				for (int i = 0 ; i < parms.Length ; i++)
					parmTypes[i] = parms[i].ParameterType;

				MethodAttributes attrs = declMethod.Attributes ^ MethodAttributes.Abstract;
				MethodBuilder method_builder = typeB.DefineMethod (declMethod.Name, attrs, declMethod.ReturnType, parmTypes);
				typeB.DefineMethodOverride (method_builder, declMethod);

				//define in/out/ref/name for each of the parameters
				for (int i = 0; i < parms.Length ; i++)
					method_builder.DefineParameter (i, parms[i].Attributes, parms[i].Name);

				ILGenerator ilg = method_builder.GetILGenerator ();
				GenHookupMethod (ilg, declMethod, sendMethodCallMethod, Mapper.GetInterfaceName (iface), declMethod.Name);
			}
		}

		static MethodInfo sendMethodCallMethod = typeof (BusObject).GetMethod ("SendMethodCall");
		static MethodInfo sendSignalMethod = typeof (BusObject).GetMethod ("SendSignal");
		static MethodInfo toggleSignalMethod = typeof (BusObject).GetMethod ("ToggleSignal");

		static Dictionary<EventInfo,DynamicMethod> hookup_methods = new Dictionary<EventInfo,DynamicMethod> ();
		public static DynamicMethod GetHookupMethod (EventInfo ei)
		{
			DynamicMethod hookupMethod;
			if (hookup_methods.TryGetValue (ei, out hookupMethod))
				return hookupMethod;

			if (ei.EventHandlerType.IsAssignableFrom (typeof (System.EventHandler)))
				Console.Error.WriteLine ("Warning: Cannot yet fully expose EventHandler and its subclasses: " + ei.EventHandlerType);

			MethodInfo declMethod = ei.EventHandlerType.GetMethod ("Invoke");

			hookupMethod = GetHookupMethod (declMethod, sendSignalMethod, Mapper.GetInterfaceName (ei), ei.Name);

			hookup_methods[ei] = hookupMethod;

			return hookupMethod;
		}

		public static DynamicMethod GetHookupMethod (MethodInfo declMethod, MethodInfo invokeMethod, string @interface, string member)
		{
			ParameterInfo[] delegateParms = declMethod.GetParameters ();
			Type[] hookupParms = new Type[delegateParms.Length+1];
			hookupParms[0] = typeof (BusObject);
			for (int i = 0; i < delegateParms.Length ; i++)
				hookupParms[i+1] = delegateParms[i].ParameterType;

			DynamicMethod hookupMethod = new DynamicMethod ("Handle" + member, declMethod.ReturnType, hookupParms, typeof (MessageWriter));

			ILGenerator ilg = hookupMethod.GetILGenerator ();

			GenHookupMethod (ilg, declMethod, invokeMethod, @interface, member);

			return hookupMethod;
		}

		//static MethodInfo getMethodFromHandleMethod = typeof (MethodBase).GetMethod ("GetMethodFromHandle", new Type[] {typeof (RuntimeMethodHandle)});
		static MethodInfo getTypeFromHandleMethod = typeof (Type).GetMethod ("GetTypeFromHandle", new Type[] {typeof (RuntimeTypeHandle)});
		static ConstructorInfo argumentNullExceptionConstructor = typeof (ArgumentNullException).GetConstructor (new Type[] {typeof (string)});
		static ConstructorInfo messageWriterConstructor = typeof (MessageWriter).GetConstructor (Type.EmptyTypes);
		static MethodInfo messageWriterWriteMethod = typeof (MessageWriter).GetMethod ("WriteComplex", new Type[] {typeof (object), typeof (Type)});
		static MethodInfo messageWriterWritePad = typeof (MessageWriter).GetMethod ("WritePad", new Type[] {typeof (int)});

		static Dictionary<Type,MethodInfo> writeMethods = new Dictionary<Type,MethodInfo> ();

		public static MethodInfo GetWriteMethod (Type t)
		{
			MethodInfo meth;

			if (writeMethods.TryGetValue (t, out meth))
				return meth;

			/*
			Type tUnder = t;
			if (t.IsEnum)
				tUnder = Enum.GetUnderlyingType (t);

			meth = typeof (MessageWriter).GetMethod ("Write", BindingFlags.ExactBinding | BindingFlags.Instance | BindingFlags.Public, null, new Type[] {tUnder}, null);
			if (meth != null) {
				writeMethods[t] = meth;
				return meth;
			}
			*/

			DynamicMethod method_builder = new DynamicMethod ("Write" + t.Name, typeof (void), new Type[] {typeof (MessageWriter), t}, typeof (MessageWriter));
			ILGenerator ilg = method_builder.GetILGenerator ();

			ilg.Emit (OpCodes.Ldarg_0);
			ilg.Emit (OpCodes.Ldarg_1);

			GenMarshalWrite (ilg, t);

			ilg.Emit (OpCodes.Ret);

			meth = method_builder;

			writeMethods[t] = meth;
			return meth;
		}

		//takes the Writer instance and the value of Type t off the stack, writes it
		public static void GenWriter (ILGenerator ilg, Type t)
		{
			Type tUnder = t;
			//bool imprecise = false;

			if (t.IsEnum) {
				tUnder = Enum.GetUnderlyingType (t);
				//imprecise = true;
			}

			//MethodInfo exactWriteMethod = typeof (MessageWriter).GetMethod ("Write", new Type[] {tUnder});
			MethodInfo exactWriteMethod = typeof (MessageWriter).GetMethod ("Write", BindingFlags.ExactBinding | BindingFlags.Instance | BindingFlags.Public, null, new Type[] {tUnder}, null);
			//ExactBinding InvokeMethod

			if (exactWriteMethod != null) {
				//if (imprecise)
				//	ilg.Emit (OpCodes.Castclass, tUnder);

				ilg.Emit (exactWriteMethod.IsFinal ? OpCodes.Call : OpCodes.Callvirt, exactWriteMethod);
			} else {
				//..boxed if necessary
				if (t.IsValueType)
					ilg.Emit (OpCodes.Box, t);

				//the Type parameter
				ilg.Emit (OpCodes.Ldtoken, t);
				ilg.Emit (OpCodes.Call, getTypeFromHandleMethod);

				ilg.Emit (messageWriterWriteMethod.IsFinal ? OpCodes.Call : OpCodes.Callvirt, messageWriterWriteMethod);
			}
		}

		//takes a writer and a reference to an object off the stack
		public static void GenMarshalWrite (ILGenerator ilg, Type type)
		{
			LocalBuilder val = ilg.DeclareLocal (type);
			ilg.Emit (OpCodes.Stloc, val);

			LocalBuilder writer = ilg.DeclareLocal (typeof (MessageWriter));
			ilg.Emit (OpCodes.Stloc, writer);

			FieldInfo[] fis = type.GetFields (BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

			//align to 8 for structs
			ilg.Emit (OpCodes.Ldloc, writer);
			ilg.Emit (OpCodes.Ldc_I4, 8);
			ilg.Emit (messageWriterWritePad.IsFinal ? OpCodes.Call : OpCodes.Callvirt, messageWriterWritePad);

			foreach (FieldInfo fi in fis) {
				Type t = fi.FieldType;

				//the Writer to write to
				ilg.Emit (OpCodes.Ldloc, writer);

				//the object parameter
				ilg.Emit (OpCodes.Ldloc, val);
				ilg.Emit (OpCodes.Ldfld, fi);

				GenWriter (ilg, t);
			}
		}

		public static void GenHookupMethod (ILGenerator ilg, MethodInfo declMethod, MethodInfo invokeMethod, string @interface, string member)
		{
			ParameterInfo[] parms = declMethod.GetParameters ();
			Type retType = declMethod.ReturnType;

			//the BusObject instance
			ilg.Emit (OpCodes.Ldarg_0);

			//MethodInfo
			/*
			ilg.Emit (OpCodes.Ldtoken, declMethod);
			ilg.Emit (OpCodes.Call, getMethodFromHandleMethod);
			*/

			//interface
			ilg.Emit (OpCodes.Ldstr, @interface);

			//special case event add/remove methods
			if (declMethod.IsSpecialName && (declMethod.Name.StartsWith ("add_") || declMethod.Name.StartsWith ("remove_"))) {
				string[] parts = declMethod.Name.Split (new char[]{'_'}, 2);
				string ename = parts[1];
				//Delegate dlg = (Delegate)inArgs[0];
				bool adding = parts[0] == "add";

				ilg.Emit (OpCodes.Ldstr, ename);

				ilg.Emit (OpCodes.Ldarg_1);

				ilg.Emit (OpCodes.Ldc_I4, adding ? 1 : 0);

				ilg.Emit (OpCodes.Tailcall);
				ilg.Emit (toggleSignalMethod.IsFinal ? OpCodes.Call : OpCodes.Callvirt, toggleSignalMethod);
				ilg.Emit (OpCodes.Ret);
				return;
			}

			//property accessor mapping
			if (declMethod.IsSpecialName) {
				if (member.StartsWith ("get_"))
					member = "Get" + member.Substring (4);
				else if (member.StartsWith ("set_"))
					member = "Set" + member.Substring (4);
			}

			//member
			ilg.Emit (OpCodes.Ldstr, member);

			//signature
			Signature inSig = Signature.Empty;
			Signature outSig = Signature.Empty;

			if (!declMethod.IsSpecialName)
			foreach (ParameterInfo parm in parms)
			{
				if (parm.IsOut)
					outSig += Signature.GetSig (parm.ParameterType.GetElementType ());
				else
					inSig += Signature.GetSig (parm.ParameterType);
			}

			ilg.Emit (OpCodes.Ldstr, inSig.Value);

			LocalBuilder writer = ilg.DeclareLocal (typeof (MessageWriter));
			ilg.Emit (OpCodes.Newobj, messageWriterConstructor);
			ilg.Emit (OpCodes.Stloc, writer);

			foreach (ParameterInfo parm in parms)
			{
				if (parm.IsOut)
					continue;

				Type t = parm.ParameterType;
				//offset by one to account for "this"
				int i = parm.Position + 1;

				//null checking of parameters (but not their recursive contents)
				if (!t.IsValueType) {
					Label notNull = ilg.DefineLabel ();

					//if the value is null...
					ilg.Emit (OpCodes.Ldarg, i);
					ilg.Emit (OpCodes.Brtrue_S, notNull);

					//...throw Exception
					string paramName = parm.Name;
					ilg.Emit (OpCodes.Ldstr, paramName);
					ilg.Emit (OpCodes.Newobj, argumentNullExceptionConstructor);
					ilg.Emit (OpCodes.Throw);

					//was not null, so all is well
					ilg.MarkLabel (notNull);
				}

				ilg.Emit (OpCodes.Ldloc, writer);

				//the parameter
				ilg.Emit (OpCodes.Ldarg, i);

				GenWriter (ilg, t);
			}

			ilg.Emit (OpCodes.Ldloc, writer);

			//the expected return Type
			ilg.Emit (OpCodes.Ldtoken, retType);
			ilg.Emit (OpCodes.Call, getTypeFromHandleMethod);

			LocalBuilder exc = ilg.DeclareLocal (typeof (Exception));
			ilg.Emit (OpCodes.Ldloca_S, exc);

			//make the call
			ilg.Emit (invokeMethod.IsFinal ? OpCodes.Call : OpCodes.Callvirt, invokeMethod);

			//define a label we'll use to deal with a non-null Exception
			Label noErr = ilg.DefineLabel ();

			//if the out Exception is not null...
			ilg.Emit (OpCodes.Ldloc, exc);
			ilg.Emit (OpCodes.Brfalse_S, noErr);

			//...throw it.
			ilg.Emit (OpCodes.Ldloc, exc);
			ilg.Emit (OpCodes.Throw);

			//Exception was null, so all is well
			ilg.MarkLabel (noErr);

			if (retType == typeof (void)) {
				//we aren't expecting a return value, so throw away the (hopefully) null return
				if (invokeMethod.ReturnType != typeof (void))
					ilg.Emit (OpCodes.Pop);
			} else {
				if (retType.IsValueType)
					ilg.Emit (OpCodes.Unbox_Any, retType);
				else
					ilg.Emit (OpCodes.Castclass, retType);
			}

			ilg.Emit (OpCodes.Ret);
		}
	}
}

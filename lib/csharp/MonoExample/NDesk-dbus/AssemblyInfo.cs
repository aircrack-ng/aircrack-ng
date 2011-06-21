// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System.Reflection;
using System.Runtime.CompilerServices;

[assembly: AssemblyFileVersion("0.6.0")]
[assembly: AssemblyInformationalVersion("0.6.0")]
[assembly: AssemblyVersion("0.6.0")]
[assembly: AssemblyTitle ("NDesk.DBus")]
[assembly: AssemblyDescription ("D-Bus IPC protocol library and CLR binding")]
[assembly: AssemblyCopyright ("Copyright (C) Alp Toker")]
[assembly: AssemblyCompany ("NDesk")]

#if STRONG_NAME
[assembly: InternalsVisibleTo ("dbus-monitor, PublicKey=0024000004800000440000000602000000240000525341318001000011000000ffbfaa640454654de78297fde2d22dd4bc4b0476fa892c3f8575ad4f048ce0721ce4109f542936083bc4dd83be5f7f97")]
[assembly: InternalsVisibleTo ("NDesk.DBus.GLib, PublicKey=0024000004800000440000000602000000240000525341318001000011000000ffbfaa640454654de78297fde2d22dd4bc4b0476fa892c3f8575ad4f048ce0721ce4109f542936083bc4dd83be5f7f97")]
[assembly: InternalsVisibleTo ("NDesk.DBus.Proxies, PublicKey=0024000004800000440000000602000000240000525341318001000011000000ffbfaa640454654de78297fde2d22dd4bc4b0476fa892c3f8575ad4f048ce0721ce4109f542936083bc4dd83be5f7f97")]
#else
[assembly: InternalsVisibleTo ("dbus-monitor")]
[assembly: InternalsVisibleTo ("NDesk.DBus.GLib")]
[assembly: InternalsVisibleTo ("NDesk.DBus.Proxies")]
#endif

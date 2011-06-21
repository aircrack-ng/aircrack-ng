// Copyright 2006 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

//We send BSD-style credentials on all platforms
//Doesn't seem to break Linux (but is redundant there)
//This may turn out to be a bad idea
#define HAVE_CMSGCRED

using System;
using System.IO;
using System.Text;

using System.Runtime.InteropServices;

using Mono.Unix;
using Mono.Unix.Native;

namespace NDesk.DBus.Transports
{
	class UnixSocket
	{
		public const short AF_UNIX = 1;
		//TODO: SOCK_STREAM is 2 on Solaris
		public const short SOCK_STREAM = 1;

		//TODO: some of these are provided by libsocket instead of libc on Solaris

		[DllImport ("libc", SetLastError=true)]
			protected static extern int socket (int domain, int type, int protocol);

		[DllImport ("libc", SetLastError=true)]
			protected static extern int connect (int sockfd, byte[] serv_addr, uint addrlen);

		[DllImport ("libc", SetLastError=true)]
			protected static extern int bind (int sockfd, byte[] my_addr, uint addrlen);

		[DllImport ("libc", SetLastError=true)]
			protected static extern int listen (int sockfd, int backlog);

		//TODO: this prototype is probably wrong, fix it
		[DllImport ("libc", SetLastError=true)]
			protected static extern int accept (int sockfd, byte[] addr, ref uint addrlen);

		//TODO: confirm and make use of these functions
		[DllImport ("libc", SetLastError=true)]
			protected static extern int getsockopt (int s, int optname, IntPtr optval, ref uint optlen);

		[DllImport ("libc", SetLastError=true)]
			protected static extern int setsockopt (int s, int optname, IntPtr optval, uint optlen);

		[DllImport ("libc", SetLastError=true)]
			public static extern int recvmsg (int s, IntPtr msg, int flags);

		[DllImport ("libc", SetLastError=true)]
			public static extern int sendmsg (int s, IntPtr msg, int flags);

		public int Handle;

		public UnixSocket (int handle)
		{
			this.Handle = handle;
		}

		public UnixSocket ()
		{
			//TODO: don't hard-code PF_UNIX and SOCK_STREAM or SocketType.Stream
			//AddressFamily family, SocketType type, ProtocolType proto

			int r = socket (AF_UNIX, SOCK_STREAM, 0);
			//we should get the Exception from UnixMarshal and throw it here for a better stack trace, but the relevant API seems to be private
			UnixMarshal.ThrowExceptionForLastErrorIf (r);
			Handle = r;
		}

		protected bool connected = false;

		//TODO: consider memory management
		public void Connect (byte[] remote_end)
		{
			int r = connect (Handle, remote_end, (uint)remote_end.Length);
			//we should get the Exception from UnixMarshal and throw it here for a better stack trace, but the relevant API seems to be private
			UnixMarshal.ThrowExceptionForLastErrorIf (r);
			connected = true;
		}

		//assigns a name to the socket
		public void Bind (byte[] local_end)
		{
			int r = bind (Handle, local_end, (uint)local_end.Length);
			UnixMarshal.ThrowExceptionForLastErrorIf (r);
		}

		public void Listen (int backlog)
		{
			int r = listen (Handle, backlog);
			UnixMarshal.ThrowExceptionForLastErrorIf (r);
		}

		public UnixSocket Accept ()
		{
			byte[] addr = new byte[110];
			uint addrlen = (uint)addr.Length;

			int r = accept (Handle, addr, ref addrlen);
			UnixMarshal.ThrowExceptionForLastErrorIf (r);
			//TODO: use the returned addr
			//TODO: fix probable memory leak here
			//string str = Encoding.Default.GetString (addr, 0, (int)addrlen);
			return new UnixSocket (r);
		}
	}

	struct IOVector
	{
		public IntPtr Base;
		public int Length;
	}

	class UnixNativeTransport : UnixTransport
	{
		protected UnixSocket socket;

		public override void Open (string path, bool @abstract)
		{
			if (String.IsNullOrEmpty (path))
				throw new ArgumentException ("path");

			if (@abstract)
				socket = OpenAbstractUnix (path);
			else
				socket = OpenUnix (path);

			//socket.Blocking = true;
			SocketHandle = (long)socket.Handle;
			Stream = new UnixStream ((int)socket.Handle);
		}

		//send peer credentials null byte
		//different platforms do this in different ways
#if HAVE_CMSGCRED
		unsafe void WriteBsdCred ()
		{
			//null credentials byte
			byte buf = 0;

			IOVector iov = new IOVector ();
			iov.Base = (IntPtr)(&buf);
			iov.Length = 1;

			msghdr msg = new msghdr ();
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;

			cmsg cm = new cmsg ();
			msg.msg_control = (IntPtr)(&cm);
			msg.msg_controllen = (uint)sizeof (cmsg);
			cm.hdr.cmsg_len = (uint)sizeof (cmsg);
			cm.hdr.cmsg_level = 0xffff; //SOL_SOCKET
			cm.hdr.cmsg_type = 0x03; //SCM_CREDS

			int written = UnixSocket.sendmsg (socket.Handle, (IntPtr)(&msg), 0);
			UnixMarshal.ThrowExceptionForLastErrorIf (written);
			if (written != 1)
				throw new Exception ("Failed to write credentials");
		}
#endif

		public override void WriteCred ()
		{
#if HAVE_CMSGCRED
			try {
				WriteBsdCred ();
			} catch {
				if (Protocol.Verbose)
					Console.Error.WriteLine ("Warning: WriteBsdCred() failed; falling back to ordinary WriteCred()");
				//null credentials byte
				byte buf = 0;
				Stream.WriteByte (buf);
			}
#else
			//null credentials byte
			byte buf = 0;
			Stream.WriteByte (buf);
#endif
		}

		protected UnixSocket OpenAbstractUnix (string path)
		{
			byte[] p = Encoding.Default.GetBytes (path);

			byte[] sa = new byte[2 + 1 + p.Length];

			//we use BitConverter to stay endian-safe
			byte[] afData = BitConverter.GetBytes (UnixSocket.AF_UNIX);
			sa[0] = afData[0];
			sa[1] = afData[1];

			sa[2] = 0; //null prefix for abstract domain socket addresses, see unix(7)
			for (int i = 0 ; i != p.Length ; i++)
				sa[3 + i] = p[i];

			UnixSocket client = new UnixSocket ();
			client.Connect (sa);

			return client;
		}

		public UnixSocket OpenUnix (string path)
		{
			byte[] p = Encoding.Default.GetBytes (path);

			byte[] sa = new byte[2 + p.Length + 1];

			//we use BitConverter to stay endian-safe
			byte[] afData = BitConverter.GetBytes (UnixSocket.AF_UNIX);
			sa[0] = afData[0];
			sa[1] = afData[1];

			for (int i = 0 ; i != p.Length ; i++)
				sa[2 + i] = p[i];
			sa[2 + p.Length] = 0; //null suffix for domain socket addresses, see unix(7)

			UnixSocket client = new UnixSocket ();
			client.Connect (sa);

			return client;
		}
	}

#if HAVE_CMSGCRED
	/*
	public struct msg
	{
		public IntPtr msg_next;
		public long msg_type;
		public ushort msg_ts;
		short msg_spot;
		IntPtr label;
	}
	*/

	unsafe struct msghdr
	{
		public IntPtr msg_name; //optional address
		public uint msg_namelen; //size of address
		public IOVector *msg_iov; //scatter/gather array
		public int msg_iovlen; //# elements in msg_iov
		public IntPtr msg_control; //ancillary data, see below
		public uint msg_controllen; //ancillary data buffer len
		public int msg_flags; //flags on received message
	}

	struct cmsghdr
	{
		public uint cmsg_len; //data byte count, including header
		public int cmsg_level; //originating protocol
		public int cmsg_type; //protocol-specific type
	}

	unsafe struct cmsgcred
	{
		public int cmcred_pid; //PID of sending process
		public uint cmcred_uid; //real UID of sending process
		public uint cmcred_euid; //effective UID of sending process
		public uint cmcred_gid; //real GID of sending process
		public short cmcred_ngroups; //number or groups
		public fixed uint cmcred_groups[16]; //groups, CMGROUP_MAX
	}

	struct cmsg
	{
		public cmsghdr hdr;
		public cmsgcred cred;
	}
#endif
}

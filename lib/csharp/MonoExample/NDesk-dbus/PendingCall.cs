// Copyright 2007 Alp Toker <alp@atoker.com>
// This software is made available under the MIT License
// See COPYING for details

using System;
using System.Threading;

namespace NDesk.DBus
{
	class PendingCall
	{
		Connection conn;
		Message reply = null;
		object lockObj = new object ();

		public PendingCall (Connection conn)
		{
			this.conn = conn;
		}

		int waiters = 0;

		public Message Reply
		{
			get {
				if (Thread.CurrentThread == conn.mainThread) {
					/*
					while (reply == null)
						conn.Iterate ();
					*/

					while (reply == null)
						conn.HandleMessage (conn.ReadMessage ());

					conn.DispatchSignals ();
				} else {
					lock (lockObj) {
						Interlocked.Increment (ref waiters);

						while (reply == null)
							Monitor.Wait (lockObj);

						Interlocked.Decrement (ref waiters);
					}
				}

				return reply;
			} set {
				lock (lockObj) {
					reply = value;

					if (waiters > 0)
						Monitor.PulseAll (lockObj);

					if (Completed != null)
						Completed (reply);
				}
			}
		}

		public event Action<Message> Completed;
	}
}

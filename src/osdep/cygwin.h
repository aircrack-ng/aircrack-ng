  /*
   *  Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
   *
   *  OS dependent API for cygwin. It relies on an external
   *  DLL to do the actual wifi stuff
   *
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2 of the License, or
   *  (at your option) any later version.
   *
   *  This program is distributed in the hope that it will be useful,
   *  but WITHOUT ANY WARRANTY; without even the implied warranty of
   *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   *  GNU General Public License for more details.
   *
   *  You should have received a copy of the GNU General Public License
   *  along with this program; if not, write to the Free Software
   *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
   */

// DLL function that have to be exported
#define CYGWIN_DLL_INIT		cygwin_init
#define CYGWIN_DLL_SET_CHAN	cygwin_set_chan
#define CYGWIN_DLL_SET_FREQ   cygwin_set_freq
#define CYGWIN_DLL_INJECT	cygwin_inject
#define CYGWIN_DLL_SNIFF	cygwin_sniff
#define CYGWIN_DLL_GET_MAC	cygwin_get_mac
#define CYGWIN_DLL_SET_MAC	cygwin_set_mac
#define CYGWIN_DLL_CLOSE	cygwin_close

/*
 * Prototypes:
 * int  CYGWIN_DLL_INIT		(char *param);
 * int  CYGWIN_DLL_SET_CHAN	(int chan);
 * int  CYGWIN_DLL_INJECT	(void *buf, int len, struct tx_info *ti);
 * int  CYGWIN_DLL_SNIFF	(void *buf, int len, struct rx_info *ri);
 * int  CYGWIN_DLL_GET_MAC	(unsigned char *mac);
 * int  CYGWIN_DLL_SET_MAC	(unsigned char *mac);
 * void CYGWIN_DLL_CLOSE	(void);
 *
 * Notes:
 * - sniff can block and inject can be called by another thread.
 * - return -1 for error.
 *
 */

/* XXX the interface is broken.  init() should return a void* that is passed to
 * each call.  This way multiple instances can be open by a single process.
 * -sorbo
 *
 */

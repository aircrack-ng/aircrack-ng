/* ripped from devine's windows airodump */

#include <string.h>
#include <dlfcn.h>
#include <windows.h>
#include <pthread.h>
#include <assert.h>
#include <err.h>

#include "osdep.h"
#include "cygwin.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#define MAGIC1		0x3E8000
#define MAGIC2		0x21
#define MAGICCHAN	0xFF636713

struct pstate
{
	void		*ps_lib;
	HANDLE		ps_adapter;
	HANDLE		ps_ctx;
	pthread_cond_t	ps_sem;
	pthread_mutex_t	ps_mtx;
	unsigned char	ps_data[4096];
	int		ps_len;

	HANDLE (*ps_peek_open_adapter)(LPSTR);
	int    (*ps_peek_start_capture)(HANDLE);
	int    (*ps_peek_request)(HANDLE, void*, void*);
	int    (*ps_peek_stop_capture)(HANDLE);
	int    (*ps_peek_close_adapter)(HANDLE);
	HANDLE (*ps_peek_create_capture_context)(HANDLE, void*, int,
						 int, void*);
} _pstate;

static struct pstate *get_ps(void)
{
	return &_pstate;
}

static int init_lib(struct pstate *ps)
{
	char *libname = "Peek.dll";
	void *lib;

	if (!(lib = dlopen(libname, RTLD_LAZY)))
		return -1;

	ps->ps_lib = lib;

	ps->ps_peek_open_adapter  = dlsym(lib, "PeekOpenAdapterA");
	ps->ps_peek_start_capture = dlsym(lib, "PeekStartCapture");
	ps->ps_peek_request	  = dlsym(lib, "PeekRequest");
	ps->ps_peek_stop_capture  = dlsym(lib, "PeekStopCapture");
	ps->ps_peek_close_adapter = dlsym(lib, "PeekCloseAdapter");
	ps->ps_peek_create_capture_context = 
		dlsym(lib, "PeekCreateCaptureContext");

	if (!(ps->ps_peek_open_adapter
	    	&& ps->ps_peek_start_capture
		&& ps->ps_peek_request
		&& ps->ps_peek_stop_capture
		&& ps->ps_peek_close_adapter
		&& ps->ps_peek_create_capture_context
	      ))
		return -1;

	return 0;
}

static void do_cleanup(struct pstate *ps)
{
	if (!ps->ps_lib)
		return;

	if (ps->ps_ctx != INVALID_HANDLE_VALUE)
		ps->ps_peek_stop_capture(ps->ps_ctx);

	if (ps->ps_adapter != INVALID_HANDLE_VALUE)
		ps->ps_peek_close_adapter(ps->ps_adapter);

	dlclose(ps->ps_lib);
}

static int set_chan(struct pstate *ps, int channel)
{
	unsigned long reqdata[139];
	OVERLAPPED iodata;

	memset(reqdata, 0, sizeof(reqdata));
	memset(&iodata, 0, sizeof(iodata));

	iodata.hEvent = CreateEvent(0, 0, 0, 0);

	reqdata[5] = 1;
	reqdata[6] = MAGICCHAN;
	reqdata[7] = (unsigned long) &channel;
	reqdata[8] = 4;

	return ps->ps_peek_request(ps->ps_adapter, reqdata, &iodata);
}

static void do_lock(struct pstate *ps)
{
	if (pthread_mutex_lock(&ps->ps_mtx))
		err(1, "pthread_mutex_lock()");
}

static void do_signal(struct pstate *ps)
{
	do_lock(ps);

	if (pthread_cond_signal(&ps->ps_sem))
		err(1, "pthread_cond_signal()");
}

static void do_wait(struct pstate *ps)
{
	do_lock(ps);

	if (pthread_cond_wait(&ps->ps_sem, &ps->ps_mtx))
		err(1, "pthread_cond_wait()");
}

static int WINAPI callback(unsigned char *data, int len, int UNUSED(caplen),
                           __int64 UNUSED(timestamp), int flags,
			   int UNUSED(arg7))
{
	struct pstate *ps = get_ps();

	if ((flags & 1) != 0)
		return 1;

	assert(len <= (int) sizeof(ps->ps_data));
	ps->ps_len = len;
	memcpy(ps->ps_data, data, ps->ps_len);

	/* tell him we wrote */
	do_signal(ps);

	/* wait for him to copy */
	do_wait(ps);

	return 1;
}

static int init_card(struct pstate *ps, char *dev)
{
	int rc;

	ps->ps_adapter = ps->ps_peek_open_adapter(dev);
	if (ps->ps_adapter == INVALID_HANDLE_VALUE)
		return -1;

	ps->ps_ctx = ps->ps_peek_create_capture_context(ps->ps_adapter,
				callback, MAGIC1, MAGIC2, NULL);

	if ((rc = ps->ps_peek_start_capture(ps->ps_ctx)))
		return rc;

	return set_chan(ps, 1);
}

int CYGWIN_DLL_INIT (char *param)
{
	struct pstate *ps = get_ps();
	int rc;

	memset(ps, 0, sizeof(*ps));
	ps->ps_adapter = INVALID_HANDLE_VALUE;
	ps->ps_ctx     = INVALID_HANDLE_VALUE;

	if ((rc = pthread_cond_init(&ps->ps_sem, NULL)))
		goto out;

	if ((rc = pthread_mutex_init(&ps->ps_mtx, NULL)))
		goto out;

	if ((rc = init_lib(ps)))
		goto out;

	if ((rc = init_card(ps, param)))
		goto out;

	return 0;
out:
	do_cleanup(ps);
	return rc;
}

int CYGWIN_DLL_SET_CHAN (int chan)
{
	struct pstate *ps = get_ps();

	return set_chan(ps, chan) ? -1 : 0;
}

int CYGWIN_DLL_INJECT (void* UNUSED(buf), int UNUSED(len),
		       struct tx_info* UNUSED(ti))
{
	return -1;
}

int CYGWIN_DLL_SNIFF (void *buf, int len, struct rx_info* UNUSED(ri))
{
	struct pstate *ps = get_ps();

	/* wait for shit */
	do_wait(ps);

	/* copy it */
	if (ps->ps_len < len)
		len = ps->ps_len;

	memcpy(buf, ps->ps_data, len);

	/* tell him we're done */
	do_signal(ps);

	return len;
}

int CYGWIN_DLL_GET_MAC (unsigned char* UNUSED(mac))
{
	return -1;
}

int CYGWIN_DLL_SET_MAC (unsigned char* UNUSED(mac))
{
	return -1;
}

void CYGWIN_DLL_CLOSE (void)
{
	struct pstate *ps = get_ps();

	do_cleanup(ps);
}

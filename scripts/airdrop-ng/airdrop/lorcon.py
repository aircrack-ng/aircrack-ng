#!/usr/bin/env python
'''
pylorcon2 - Python wrapper for LORCON 2
By: Tom Wambold <tom5760@gmail.com>
Home: http://github.com/tom5760/pylorcon2/
LORCON: http://802.11ninja.net/

'''
import pdb
import ctypes
from ctypes.util import find_library

class LorconError(Exception): pass

class StructLorcon(ctypes.Structure): pass

# Function Pointers
LORCON_DRV_INIT = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(StructLorcon))
LORCON_DRV_PROBE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)

# Forward declare this struct
class StructDriver(ctypes.Structure):
    pass

# We need to do this since this struct references itself
StructDriver._fields_ = (
        ('name', ctypes.c_char_p),
        ('details', ctypes.c_char_p),

        ('init_func', LORCON_DRV_INIT),
        ('probe_func', LORCON_DRV_PROBE),

        ('next', ctypes.POINTER(StructDriver)),
    )

class Lorcon(object):
    'Represents the LORCON library.'

    def __init__(self, lib_path=None):
        '''Instantiate the LORCON library.

        lib_path - Path to LORCON shared library.  If None, it is autodetected.

        '''

        if lib_path is None:
            # Look for -lorcon2
            lib_path = find_library('orcon2')

        self.lib = ctypes.cdll.LoadLibrary(lib_path)

        # Set argument and return types for functions
        self.lib.lorcon_list_drivers.argtypes = None
        self.lib.lorcon_list_drivers.restype = ctypes.POINTER(StructDriver)

        self.lib.lorcon_find_driver.argtypes = [ctypes.c_char_p]
        self.lib.lorcon_find_driver.restype = ctypes.POINTER(StructDriver)

        self.lib.lorcon_auto_driver.argtypes = [ctypes.c_char_p]
        self.lib.lorcon_auto_driver.restype = ctypes.POINTER(StructDriver)

        self.lib.lorcon_free_driver_list.argtypes = [ctypes.POINTER(StructDriver)]
        self.lib.lorcon_free_driver_list.restype = None

        self.lib.lorcon_create.argtypes = [ctypes.c_char_p,
                ctypes.POINTER(StructDriver)]
        self.lib.lorcon_create.restype = ctypes.POINTER(StructLorcon)

        self.lib.lorcon_free.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_free.restype = None

        self.lib.lorcon_get_error.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_error.restype = ctypes.c_char_p

        self.lib.lorcon_get_timeout.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_timeout.restype = ctypes.c_int

        self.lib.lorcon_set_timeout.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_int]
        self.lib.lorcon_set_timeout.restype = None

        self.lib.lorcon_set_timeout.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_set_timeout.restype = ctypes.c_int

        self.lib.lorcon_open_inject.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_open_inject.restype = ctypes.c_int
        self.lib.lorcon_open_inject.errcheck = self._errcheck_int

        self.lib.lorcon_open_monitor.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_open_monitor.restype = ctypes.c_int
        self.lib.lorcon_open_monitor.errcheck = self._errcheck_int

        self.lib.lorcon_get_vap.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_vap.restype = ctypes.c_char_p

        self.lib.lorcon_set_vap.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_char_p]
        self.lib.lorcon_set_vap.restype = None

        self.lib.lorcon_get_capiface.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_capiface.restype = ctypes.c_char_p

        self.lib.lorcon_get_driver_name.argtypes = [
                ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_driver_name.restype = ctypes.c_char_p

        # TODO: These are not implemented in Lorcon2 yet
        #self.lib.lorcon_get_datalink.argtypes = [ctypes.POINTER(StructLorcon)]
        #self.lib.lorcon_get_datalink.restype = ctypes.c_int

        #self.lib.lorcon_set_datalink.argtypes = [ctypes.POINTER(StructLorcon),
        #        ctypes.c_int]
        #self.lib.lorcon_set_datalink.restype = ctypes.c_int
        #self.lib.lorcon_set_datalink.errcheck = self._errcheck_int

        self.lib.lorcon_get_channel.argtypes = [ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_channel.restype = ctypes.c_int

        self.lib.lorcon_set_channel.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_int]
        self.lib.lorcon_set_channel.restype = ctypes.c_int
        self.lib.lorcon_set_channel.errcheck = self._errcheck_int

        self.lib.lorcon_get_hwmac.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8))]
        self.lib.lorcon_get_hwmac.restype = ctypes.c_int
        self.lib.lorcon_get_hwmac.errcheck = self._errcheck_int

        self.lib.lorcon_set_hwmac.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_int, ctypes.POINTER(ctypes.c_uint8)]
        self.lib.lorcon_set_hwmac.restype = ctypes.c_int
        self.lib.lorcon_set_hwmac.errcheck = self._errcheck_int

        self.lib.lorcon_get_pcap.argtypes = [ctypes.POINTER(StructLorcon)]
        # TODO: Maybe make a real ctypes type for this?  Should be struct pcap_t
        self.lib.lorcon_get_pcap.restype = ctypes.c_void_p

        self.lib.lorcon_get_selectable_fd.argtypes = [
                ctypes.POINTER(StructLorcon)]
        self.lib.lorcon_get_selectable_fd.restype = ctypes.c_int

        # TODO: lorcon_next_ex goes here

        self.lib.lorcon_set_filter.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_char_p]
        self.lib.lorcon_set_filter.restype = ctypes.c_int
        self.lib.lorcon_set_filter.errcheck = self._errcheck_int

        # TODO: lorcon_set_compiled_filter goes here
        # TODO: lorcon_pcap_loop goes here
        # TODO: lorcon_pcap_dispatch goes here

        self.lib.lorcon_breakloop.argtypes = None
        self.lib.lorcon_breakloop.restype = None

        # TODO: Wrap the lorcon_packet stuff
        #self.lib.lorcon_inject.argtypes = [ctypes.POINTER(StructLorcon),
        #        ctypes.POINTER(StructPacket)]
        #self.lib.lorcon_inject.restype = ctypes.c_int
        #self.lib.lorcon_inject.errcheck = self._errcheck_int

        self.lib.lorcon_send_bytes.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.lorcon_send_bytes.restype = ctypes.c_int
        self.lib.lorcon_send_bytes.errcheck = self._errcheck_int

        self.lib.lorcon_get_version.argtypes = None
        self.lib.lorcon_get_version.restype = ctypes.c_ulong

        self.lib.lorcon_add_wepkey.argtypes = [ctypes.POINTER(StructLorcon),
                ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.lorcon_add_wepkey.restype = ctypes.c_int
        self.lib.lorcon_add_wepkey.errcheck = self._errcheck_int

    def list_drivers(self):
        'List all drivers LORCON is compiled with.'
        return _generate_driver_list(self.lib, self.lib.lorcon_list_drivers())

    def find_driver(self, driver):
        return Driver(self.lib, self.lib.lorcon_find_driver(driver))

    def auto_driver(self, interface):
        return Driver(self.lib, self.lib.lorcon_auto_driver(interface))

    def create(self, interface, driver):
        return Context(self.lib, self.lib.lorcon_create(interface, driver))

    def _errcheck_int(self, result, func, args):
        'Raises an exception if the return value is less than 0'
        if result < 0:
            raise LorconError(self.lib.lorcon_get_error(args[0]))
        return result

class Driver(object):
    '''Represents a driver struct.

    Automatically frees memory when this object is garbage collected.

    '''
    def __init__(self, lib, ptr):
        '''lib = reference to the lorcon library
           ptr = ctypes pointer to a StructDriver

       '''
        self.lib = lib
        self._as_parameter_ = ptr
        self.contents = ptr.contents

    def __del__(self):
        self.lib.lorcon_free_driver_list(self)

    def __str__(self):
        return self.name

    name = property(lambda self: self.contents.name)
    details = property(lambda self: self.contents.details)

class Context(object):
    'Represents a LORCON context struct.'

    def __init__(self, lib, ptr):
        '''lib = reference to the lorcon library
           ptr = ctypes pointer to a StructLorcon

        '''
        self.lib = lib
        self._as_parameter_ = ptr
        self.contents = ptr.contents

    def __del__(self):
        self.lib.lorcon_free(self)

    def open_inject(self):
        'Open an interface for inject.'
        self.lib.lorcon_open_inject(self)

    def open_monitor(self):
        'Open an interface in monitor mode (may also enable injection).'
        self.lib.lorcon_open_monitor(self)

    def open_injmon(self):
        'Open an interface in inject+monitor mode.'
        self.lib.lorcon_open_injmon(self)

    def close(self):
        'Close interface.'
        self.lib.lorcon_close(self)

    def fileno(self):
        'For use in the "select" package'
        return self.selectable_fd

    def next_ex(self):
        raise NotImplementedError()

    def set_filter(self, filter):
        self.lib.lorcon_set_filter(self, filter)

    def set_compiled_filter(self, filter):
        raise NotImplementedError()

    def pcap_loop(self, count, callback):
        raise NotImplementedError()

    def pcap_dispatch(self, count, callback):
        raise NotImplementedError()

    def pcap_breakloop(self):
        self.lib.lorcon_breakloop(self)

    def inject(self, packet):
        # TODO: Wrap the lorcon_packet stuff
        raise NotImplementedError()
        #return self.lib.lorcon_inject(self, packet)

    def send_bytes(self, data):
        buf = (ctypes.c_ubyte * len(data))(*[ord(x) for x in data])
        return self.lib.lorcon_send_bytes(self, len(buf), buf)

    def add_wepkey(self, bssid, key):
        return self.lib.lorcon_add_wepkey(self, bssid, key, len(key))

    # Properties (Replaces getters/setters

    version = property(lambda self: self.lib.lorcon_get_version(self))

    error = property(lambda self: self.lib.lorcon_get_error(self),
            doc='Return the most recent error.')

    timeout = property(
            lambda self: self.lib.lorcon_get_timeout(self),
            lambda self, x: self.lib.lorcon_set_timeout(self, x),
            doc='''Set a capture timeout (equivalent to the timeout value in
            pcap_open, but with implications for non-pcap sources as well).
            Timeout value is in ms.''')

    vap = property(
            lambda self: self.lib.lorcon_get_vap(self),
            lambda self, x: self.lib.lorcon_set_vap(self, x),
            doc='Set/Get the VAP (if we use VAPs).')

    capiface = property(
            lambda self: self.lib.lorcon_get_capiface(self),
            doc='Get the interface we\'re capturing from.')

    driver_name = property(
            lambda self: self.lib.lorcon_get_driver_name(self),
            doc='Get the driver.')

    # TODO: This isn't defined in Lorcon2 yet
    #datalink = property(
    #        lambda self: self.lib.lorcon_get_datalink(self),
    #        lambda self, x: self.lib.lorcon_set_datalink(self, x),
    #        doc='Datalink layer info')

    channel = property(
            lambda self: self.lib.lorcon_get_channel(self),
            lambda self, x: self.lib.lorcon_set_channel(self, x),
            doc='Get/set channel/frequency')

    pcap = property(
            lambda self: self.lib.lorcon_get_pcap(self),
            doc='Get a pcap_t')

    selectable_fd = property(
            lambda self: self.lib.lorcon_get_selectable_fd(self))

    # These properties are a bit more complicated, so define them using
    # decorators

    @property
    def hwmac(self):
        '''Get/set MAC address, returns length of MAC and allocates in **mac,
        caller is responsible for freeing this memory.  Different PHY types may
        have different MAC lengths.

        For 802.11, MAC is always 6 bytes.

        A length of 0 indicates no set MAC on this PHY.  Negative numbers
        indicate error fetching MAC from hardware.

        '''
        mac = ctypes.POINTER(ctypes.c_uint8)()
        maclen = self.lib.lorcon_get_hwmac(self, ctypes.byref(mac))
        if maclen:
            return mac[0:maclen]
        raise LorconError('No MAC on this PHY')

    @hwmac.setter
    def hwmac(self, mac):
        'mac should be a list of 8 bit integers'
        mac_array = (ctypes.c_uint8 * len(mac))(*mac)
        return self.lib.lorcon_set_hwmac(self, len(mac_array), mac_array)

def _generate_driver_list(lib, ptr):
    '''Creates a list of Driver objects from a pointer to a driver list from
    lorcon_list_drivers.

    This makes sure each Driver object can be independently garbage collected.

    '''
    driver_list = []
    while True:
        try:
            driver_list.append(Driver(lib, ptr))
        except ValueError:
            break
        ptr = ptr.contents.next

    # Remove the "next" pointers in each driver, so that they can be garbage
    # collected independently
    for driver in driver_list:
        driver.contents.next = None

    return driver_list

if __name__ == '__main__':
    l = Lorcon('/tmp/lorcon/lib/liborcon2.so')
    driver = l.auto_driver('wlan17')
    context = l.create('wlan17', driver)
    context.open_inject()
    z = 0
    while True:
        z += 1
        context.channel=6
        print 'sending packet',z
        context.send_bytes('\x0c\x00\x00\x00\xDE\xAD\xBE\xEF\x00\x00\xDE\xAD\xBE\xEF\x00\x00\xDE\xAD\xBE\xEF\x00\x00\x70\x6a\x0b\x00')

// Function to be used by cygwin
void airpcap_close(void);
int airpcap_get_mac(void *mac);
int airpcap_set_mac(void *mac);
int airpcap_sniff(void *buf, int len, struct rx_info *ri);
int airpcap_inject(void *buf, int len, struct tx_info *ti);
int airpcap_init(char *param);
int airpcap_set_chan(int chan);

int isAirpcapDevice(const char * iface);


//int printErrorCloseAndReturn(const char * err, int retValue);


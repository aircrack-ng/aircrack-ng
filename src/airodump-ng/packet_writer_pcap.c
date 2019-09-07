#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet_writer_pcap.h"
#include "packet_writer_private.h"
#include "aircrack-ng/support/pcap_local.h"

#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>

struct pcap_writer_context_st
{
	FILE * fp;
};

static void write_cap_file(FILE * fp,
						   uint8_t const * const h80211,
						   size_t const caplen,
						   int32_t const ri_power)
{
	struct pcap_pkthdr pkh;
	struct timeval tv;

	if (fp == NULL || caplen < 10)
	{
		goto done;
	}

	gettimeofday(&tv, NULL);

	pkh.len = pkh.caplen = caplen;
	pkh.tv_sec = (int32_t) tv.tv_sec;
	pkh.tv_usec = (int32_t)((tv.tv_usec & ~0x1ff) + ri_power + 64);

	/* Write the header. */
	if (fwrite(&pkh, 1, sizeof(pkh), fp) != sizeof(pkh))
	{
		perror("fwrite(packet header) failed");
		goto done;
	}

	/* Now write the data. */
	if (fwrite(h80211, 1, caplen, fp) != caplen)
	{
		perror("fwrite(packet data) failed");
		goto done;
	}

	fflush(fp);

done:
	return;
}

static void context_free(struct pcap_writer_context_st * const context)
{
	free(context);
}

static void pcap_write(void * const priv,
					   uint8_t const * const packet,
					   size_t const packet_length,
					   int32_t const ri_power)
{
	struct pcap_writer_context_st * const context = priv;

	write_cap_file(context->fp, packet, packet_length, ri_power);
}

static void pcap_context_close(struct pcap_writer_context_st * const context)
{
	if (context == NULL)
	{
		goto done;
	}

	if (context->fp != NULL)
	{
		fclose(context->fp);
	}

	context_free(context);

done:
	return;
}

static void pcap_close(void * const priv)
{
	struct pcap_writer_context_st * const context = priv;

	pcap_context_close(context);
}

static bool write_file_header(FILE * const fp)
{
	bool wrote_header;
	struct pcap_file_header pfh;

	pfh.magic = TCPDUMP_MAGIC;
	pfh.version_major = PCAP_VERSION_MAJOR;
	pfh.version_minor = PCAP_VERSION_MINOR;
	pfh.thiszone = 0;
	pfh.sigfigs = 0;
	pfh.snaplen = 65535;
	pfh.linktype = LINKTYPE_IEEE802_11;

	if (fwrite(&pfh, 1, sizeof pfh, fp) != sizeof pfh)
	{
		perror("fwrite(pcap file header) failed");

		wrote_header = false;
		goto done;
	}

	fflush(fp);

	wrote_header = true;

done:
	return wrote_header;
}

struct pcap_writer_context_st * pcap_context_open(char const * const filename)
{
	bool success;
	struct pcap_writer_context_st * context = calloc(1, sizeof *context);

	if (context == NULL)
	{
		success = false;
		goto done;
	}

	context->fp = fopen(filename, "wb+");
	if (context->fp == NULL)
	{
		success = false;
		goto done;
	}

	if (!write_file_header(context->fp))
	{
		success = false;
		goto done;
	}

	success = true;

done:
	if (!success)
	{
		pcap_context_close(context);
		context = NULL;
	}

	return context;
}

bool pcap_packet_writer_open(
	struct packet_writer_context_st * const writer_context,
	char const * const filename)
{
	bool success;
	struct pcap_writer_context_st * const context = pcap_context_open(filename);

	if (context == NULL)
	{
		success = false;
		goto done;
	}

	writer_context->priv = context;
	writer_context->write = pcap_write;
	writer_context->close = pcap_close;

	success = true;

done:
	return success;
}

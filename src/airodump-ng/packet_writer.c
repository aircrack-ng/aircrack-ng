#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet_writer.h"
#include "packet_writer_private.h"
#include "packet_writer_pcap.h"

#include <stdlib.h>

void packet_writer_write(struct packet_writer_context_st * const context,
						 uint8_t const * const packet,
						 size_t const packet_length,
						 int32_t const ri_power)
{
	if (context == NULL)
	{
		goto done;
	}

	context->write(context->priv, packet, packet_length, ri_power);

done:
	return;
}

void packet_writer_close(struct packet_writer_context_st * const context)
{
	if (context == NULL)
	{
		goto done;
	}

	if (context->close != NULL)
	{
		context->close(context->priv);
	}

	free(context);

done:
	return;
}

struct packet_writer_context_st *
packet_writer_open(packet_writer_type_t const packet_writer_type,
				   char const * const filename)
{
	bool success;
	struct packet_writer_context_st * context = calloc(1, sizeof *context);

	if (context == NULL)
	{
		success = false;
		goto done;
	}

	switch (packet_writer_type)
	{
		case packet_writer_type_pcap:
			if (!pcap_packet_writer_open(context, filename))
			{
				success = false;
				goto done;
			}
			break;

		default:
			success = false;
			goto done;
	}

	success = true;

done:
	if (!success)
	{
		packet_writer_close(context);
		context = NULL;
	}

	return context;
}

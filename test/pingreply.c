/* pingreply.c - Ping reply
 *
 * DESCIPTION
 *
 * Replies to all ping requests. Useful for testing sniffing/injecting
 * packets with airtun-ng.
 *
 * USAGE
 *
 * ./pingreply <iface>
 *
 * INSTALL
 *
 * cc -lpcap -o pingreply pingreply.c
 *
 * LICENSE
 *
 * Copyright (c) 2015, Jorn van Engelen <spamme@quzart.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>


struct eth_hdr {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;
};

struct ip_hdr {
    unsigned char vhl;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short off;
    unsigned char ttl;
    unsigned char proto;
    unsigned short chksum;
    unsigned char src[4];
    unsigned char dst[4];
};

struct icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short chksum;
    unsigned short id;
    unsigned short seq;
    unsigned char data[];
};

struct eth_ip_icmp_reply {
    struct eth_hdr eth;
    struct ip_hdr ip;
    struct icmp_hdr icmp;
};



pcap_t *p;
char errbuf[PCAP_ERRBUF_SIZE];


short internet_chksum( unsigned char *hdr, int len )
{
    unsigned int sum = 0;

    while ( len > 1 )
    {
        sum += * (unsigned short*) hdr;
        hdr += 2;
        len -= 2;
    }

    if ( len > 0 )
        sum += * (unsigned char*) hdr;

    while ( sum >> 16 )
        sum = (sum >> 16) + (sum & 0xffff);

    return ~sum;
}

void reply_icmp_echo(
    const struct eth_hdr *eth,
    const struct ip_hdr *ip,
    const struct icmp_hdr *icmp,
    int len)
{
    unsigned char *ptr;
    struct eth_ip_icmp_reply *reply;

    reply = (struct eth_ip_icmp_reply*) calloc( sizeof(struct eth_ip_icmp_reply) + len, 1 );
    assert( reply != NULL );

    memcpy( reply->eth.src, eth->dst, 6 );
    memcpy( reply->eth.dst, eth->src, 6 );
    reply->eth.type = htons(0x0800);

    reply->ip.vhl = 0x45;
    reply->ip.length = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + len);
    reply->ip.id = htons(0xCAFE);
    reply->ip.ttl = 0x80;
    reply->ip.proto = 0x01;
    memcpy( reply->ip.src, ip->dst, 4 );
    memcpy( reply->ip.dst, ip->src, 4 );

    reply->icmp.type = 0x00;
    reply->icmp.code = 0x00;
    reply->icmp.id = icmp->id;
    reply->icmp.seq = icmp->seq;
    memcpy( reply->icmp.data, icmp->data, len );
    
    reply->ip.chksum = internet_chksum( (unsigned char*) &(reply->ip), sizeof(struct ip_hdr) );
    reply->icmp.chksum = internet_chksum( (unsigned char*) &(reply->icmp), sizeof(struct icmp_hdr) + len );

    printf( "Sent icmp echo reply to: %i.%i.%i.%i.\n", ip->src[0], ip->src[1], ip->src[2], ip->src[3] );
    
    if ( pcap_inject( p, reply, sizeof(struct eth_ip_icmp_reply) + len ) == -1 )
    {
        fprintf( stderr, "Could not inject packet: %s\n", pcap_geterr( p ) );
    }

    free( reply );
}

    
void receive_packet(
    unsigned char *args,
    const struct pcap_pkthdr *header,
    const unsigned char *packet)
{
    int len = header->caplen;
    int ip_hdr_len;
    const struct eth_hdr *eth;
    const struct ip_hdr *ip;
    const struct icmp_hdr *icmp;
    
    len -= sizeof(struct eth_hdr);
    if ( len < 0 )
        return;

    eth = (struct eth_hdr*) packet;
    packet += sizeof(struct eth_hdr);
    
    /* Packet must be IPv4 */
    if ( ntohs(eth->type) != 0x0800 )
        return;

    if ( len < sizeof(struct ip_hdr) )
        return;

    ip = (struct ip_hdr*) packet;
    if ( ntohs( ip->length ) != len )
        return;
    if ( ip->vhl >> 4 != 4 )
        return;
    
    ip_hdr_len = ( ip->vhl & 0x0F ) * 4;
    if ( ip_hdr_len < sizeof(struct ip_hdr) )
        return;
    
    len -= ip_hdr_len;
    if ( len < 0 )
        return;
    
    packet += ip_hdr_len;
    
    /* Packet must be ICMP */
    if ( ip->proto != 0x01 )
        return;

    len -= sizeof(struct icmp_hdr);
    if ( len <  0 )
        return;

    icmp = (struct icmp_hdr*) packet;
    packet += sizeof(struct icmp_hdr);

    /* Packet must be echo request */
    if ( ! ( icmp->type == 0x08 && icmp->code == 0x00 ) )
        return;

    usleep( 2000 );
    
    reply_icmp_echo( eth, ip, icmp, len );
}

int main( int argc, char *argv[] )
{
    struct bpf_program fp;

    if ( argc != 2 )
    {
        fprintf( stderr, "Usage: pingrep <dev>\n" );
        return 2;
    }

    p = pcap_open_live( argv[1], 1024, 1, 0, errbuf );
    if ( p == NULL )
    {
        fprintf( stderr, "Could not open device %s: %s\n", argv[1], errbuf );
        return 2;
    }

    if ( pcap_datalink( p ) != DLT_EN10MB )
    {
        fprintf( stderr, "Expected Ethernet from device %s.\n", argv[1] );
        return 2;
    }

    if ( pcap_compile( p, &fp, "icmp[icmptype] = icmp-echo", 0, PCAP_NETMASK_UNKNOWN ) == -1 )
    {
        fprintf( stderr, "Could not parse filter: %s\n", pcap_geterr( p ) );
        return 2;
    }

    if ( pcap_setfilter( p, &fp ) == -1 )
    {
        fprintf( stderr, "Could not install filter: %s\n", pcap_geterr( p ) );
        return 2;
    }

    printf( "Receiving packets ...\n" );
    pcap_loop( p, 0, receive_packet, NULL );

    pcap_freecode( &fp );
    pcap_close( p );

    printf( "Done.\n" );
    
    return 0;
}

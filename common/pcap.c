/* pcap.c

   pcap socket interface code, originally developed to get decent AIX
   functionality.

 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 *
 * This software was contributed to Internet Systems Consortium
 * by Niklas Edmundsson, Academic Computer Club, Umea University, Sweden
 *
 */

#ifndef lint
static char copyright[] =
"$Id$ Copyright (c) 2007 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/* This is a receive-only interface */
#ifdef USE_PCAP_RECEIVE

#include <pcap.h>
#include <net/bpf.h>

/* Max size of packet to capture, this should really come from some define
   or variable in dhcpd... */
#define PCAP_SNAPLEN 4096

/* Reinitializes the specified interface after an address change.   This
   is not required for packet-filter APIs. */
void if_reinitialize_receive (info)
	struct interface_info *info;
{
}

void if_register_receive (struct interface_info *info)
{
    pcap_t              *pcapdev;
    char                 ebuf[PCAP_ERRBUF_SIZE];
    char                 filterstr[1024];
    struct bpf_program   filter;
    bpf_u_int32          netmask;


    pcapdev = pcap_open_live(info->name, PCAP_SNAPLEN, 0, 0, ebuf);
    if(pcapdev == NULL) {
        log_fatal("pcap_open_live failed on %s: %s", info->name, ebuf);
    }

    sprintf(filterstr,
                "udp dst port %d " /* UDP to the right port */
                "and ip[6:2] & 0x1fff = 0" /* Only non-fragmented packets */
            , ntohs (local_port)
            );

    /* FIXME: Should probably get netmask from
       info->shared_network->subnets.netmask instead, but I think it's only
       used when compiling a few filter directives */
    netmask = 0xffffff00;
    if(pcap_compile(pcapdev, &filter, filterstr, 1, netmask) != 0) {
        log_fatal("pcap_compile failed: %s", pcap_geterr(pcapdev));
    }

    if(pcap_setfilter(pcapdev, &filter) != 0) {
        log_fatal("pcap_setfilter failed: %s", pcap_geterr(pcapdev));
    }

    /* DHCPD wants an fd to do select/poll on */
    info -> rfdesc = pcap_fileno(pcapdev);

    /* We need to keep our pcap device pointer, unfortunately DHCPD doesn't
       provide a generic data pointer for us, so we have to store it in
       the pointer meant for the read buffer. */
    info->rbuf = (void *) pcapdev;

    if (!quiet_interface_discovery)
        log_info ("Listening on PCAP/%s/%s%s%s",
                info -> name,
                print_hw_addr (info -> hw_address.hbuf [0],
                    info -> hw_address.hlen - 1,
                    &info -> hw_address.hbuf [1]),
                (info -> shared_network ? "/" : ""),
                (info -> shared_network ?
                 info -> shared_network -> name : ""));
}

void if_deregister_receive (struct interface_info *info)
{
    pcap_t  *pcapdev = (void *) info->rbuf;

    pcap_close(pcapdev);
    info->rbuf = NULL;
    info->rfdesc = -1;

    if (!quiet_interface_discovery)
        log_info ("Disabling input on PCAP/%s/%s%s%s",
                info -> name,
                print_hw_addr (info -> hw_address.hbuf [0],
                    info -> hw_address.hlen - 1,
                    &info -> hw_address.hbuf [1]),
                (info -> shared_network ? "/" : ""),
                (info -> shared_network ?
                 info -> shared_network -> name : ""));
}

struct callback_info {
    struct interface_info *interface; /* The interface used */
    unsigned char   *buf;    /* Buffer pointer */
    size_t           buflen; /* Length of buffer */
    struct sockaddr_in *from; /* Source IP */
    struct hardware *hfrom;   /* Source MAC */
    size_t           caplen; /* Actual length of captured packet */
};

/* Callback for pcap_dispatch() */
static void packet_callback(u_char *user, const struct pcap_pkthdr *phdr,
                            const u_char *pdata)
{
    struct callback_info    *cinfo = (void *) user;
    size_t                   caplen = phdr->caplen;
    int                      rc;
    struct sockaddr_in       from;
    struct hardware          hfrom;
    unsigned                 paylen;

    if(caplen > PCAP_SNAPLEN) {
        log_fatal("pcap caplen %u > snaplen %u, this is known to be caused by "
                  "compiling in 64bit mode due to a bugs in pcap on AIX",
                  caplen, PCAP_SNAPLEN);
    }
    if(caplen < phdr->len) {
        /* Captured part of packet shorter than packet length, ignore */
        log_error ("packet_callback failed on %s: caplen %u < len %u",
                    cinfo->interface->name, caplen, phdr->len);

        return;
    }
    if(caplen > cinfo->buflen) {
        log_error ("packet_callback failed on %s: caplen %u > buflen %lu",
                   cinfo->interface->name, caplen, cinfo->buflen);
        return;
    }

    /* Decode the physical header... */
    rc = decode_hw_header (cinfo->interface, (unsigned char *) pdata, 0,
                           &hfrom);

    /* If a physical layer checksum failed, skip this packet. */
    if (rc < 0) {
        log_error ("packet_callback failed on %s: decode_hw_header fail",
                    cinfo->interface->name);
        return;
    }

    /* Skip over the parsed hw header */
    pdata += rc;
    caplen -= rc;

    /* Decode the IP and UDP headers... */
    rc = decode_udp_ip_header (cinfo->interface, (unsigned char *) pdata, 0,
                               &from, caplen, &paylen);

    /* If the IP or UDP checksum was bad, skip the packet... */
    if (rc < 0) {
        log_error ("packet_callback failed on %s: decode_udp_ip_header fail",
                    cinfo->interface->name);
        return;
    }

    /* Skip over the parsed udp header */
    pdata += rc;
    caplen -= rc;

    /* All OK, copy data to target buffers */
    memcpy(cinfo->hfrom, &hfrom, sizeof(hfrom));
    memcpy(cinfo->from, &from, sizeof(from));
    memcpy(cinfo->buf, pdata, paylen);
    cinfo->caplen = paylen;

    return;
}


ssize_t receive_packet (struct interface_info *interface, unsigned char *buf,
                        size_t len, struct sockaddr_in *from,
                        struct hardware *hfrom)
{
    pcap_t                  *pcapdev = (void *) interface->rbuf;
    int                      rc;
    struct callback_info     cinfo;

    /* pcap is itself callback-oriented, so to wedge it into the DHCPD
       structure we provide a callback that merely stores the data so we can
       get a hold of it. AIX 5.3 doesn't have pcap_next_ex() which would have
       been a more elegant solution */

    cinfo.interface = interface;
    cinfo.buf = buf;
    cinfo.buflen = len;
    cinfo.from = from;
    cinfo.hfrom = hfrom;
    cinfo.caplen = 0;

    /* FIXME: Right now we dispatch all packets in a received buffer, but
              only report the last one to DHCPD. This shouldn't be a problem
              unless you have really large amounts of traffic since normally
              there will be only one packet in each buffer.  */
    rc = pcap_dispatch(pcapdev, -1, packet_callback, (void *) &cinfo);

    if(rc < 0) {
        log_error ("receive_packet failed on %s: %s", interface->name,
                   pcap_geterr(pcapdev));

        /* Sometimes stuff get stuck somehow and we keep getting:

           read: A memory address is not in the address space for the process.

           at least on AIX 5.1... So let's assume it's serious when dispatch
           fails and try to recover by reinitialize the interface
         */

        log_error ("Trying to recover by reinitializing interface %s",
                   interface->name);
        if_deregister_receive(interface);
        if_register_receive(interface);

        return(0);
    }
    if(rc == 0) {
        return(0);
    }

    /* If packet_callback has found a valid packet it would have updated
       caplen. */
    return cinfo.caplen;
}

int can_unicast_without_arp (ip)
	struct interface_info *ip;
{
	return 1;
}

int can_receive_unicast_unconfigured (ip)
	struct interface_info *ip;
{
	return 1;
}

int supports_multiple_interfaces (ip)
	struct interface_info *ip;
{
	return 1;
}

void maybe_setup_fallback ()
{
	isc_result_t status;
	struct interface_info *fbi = (struct interface_info *)0;
	if (setup_fallback (&fbi, MDL)) {
		if_register_fallback (fbi);
		status = omapi_register_io_object ((omapi_object_t *)fbi,
						   if_readsocket, 0,
						   fallback_discard, 0, 0);
		if (status != ISC_R_SUCCESS)
			log_fatal ("Can't register I/O handle for %s: %s",
				   fbi -> name, isc_result_totext (status));
		interface_dereference (&fbi, MDL);
	}
}
#endif /* USE_PCAP_RECEIVE */

/*
vim:sw=4:sts=4:cindent:
*/

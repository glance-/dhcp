/* ndd.c

   ndd socket interface code, to be able to do interface-specific packet
   transmit on AIX similar to what bpf can on other platforms.

   Inspired by bpf.c

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
 * by Anton Lundin, Academic Computer Club, Umea University, Sweden
 *
 */

#ifndef lint
static char copyright[] =
"$Id$ Copyright (c) 2007 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/* This is a transmit-only interface */
#ifdef USE_NDD_SEND

# include <sys/ndd.h>
# include <sys/ndd_var.h>
# include <net/if_dl.h>
# include "includes/netinet/if_ether.h"


/* Reinitializes the specified interface after an address change, we bind
   directly to the interface and are not affected by this */
void if_reinitialize_send (struct interface_info *info)
{
}

void if_register_send (struct interface_info *info)
{
    struct sockaddr_ndd_8022 sa;

    if (( info -> wfdesc = socket(AF_NDD, SOCK_DGRAM, 0)) == -1) {
        log_fatal ("NDD: open data link on interface %s : socket: %m",
                   info -> name);
    }

    sa.sndd_8022_family = AF_NDD;
    sa.sndd_8022_len = sizeof(sa);
    sa.sndd_8022_filtertype = NS_ETHERTYPE;
    sa.sndd_8022_ethertype = 0xfeed; /* dummy enet type */
    sa.sndd_8022_filterlen = sizeof(struct ns_8022);
    strcpy(sa.sndd_8022_nddname, info -> name);

    if (connect(info -> wfdesc, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        log_fatal("NDD: connect on interface %s: %m",
                  info -> name);
    }

    if (!quiet_interface_discovery)
        log_info ("Sending on   NDD/%s/%s%s%s",
                info -> name,
                print_hw_addr (info -> hw_address.hbuf [0],
                    info -> hw_address.hlen - 1,
                    &info -> hw_address.hbuf [1]),
                (info -> shared_network ? "/" : ""),
                (info -> shared_network ?
                 info -> shared_network -> name : ""));
}


void if_deregister_send (struct interface_info *info)
{
    close (info -> wfdesc);
    info -> wfdesc = -1;

    if (!quiet_interface_discovery)
        log_info ("Disabling output on NDD/%s/%s%s%s",
                info -> name,
                print_hw_addr (info -> hw_address.hbuf [0],
                    info -> hw_address.hlen - 1,
                    &info -> hw_address.hbuf [1]),
                (info -> shared_network ? "/" : ""),
                (info -> shared_network ?
                 info -> shared_network -> name : ""));
}


ssize_t send_packet (struct interface_info * interface, struct packet *packet,
        struct dhcp_packet *raw, size_t len, struct in_addr from,
        struct sockaddr_in *to, struct hardware *hto)
{
	unsigned hbufp = 0, ibufp = 0;
	double hw [4];
	double ip [32];
	struct iovec iov [3];
	int result;

	if (!strcmp (interface -> name, "fallback")) {
            return send_fallback (interface, packet, raw, len, from, to, hto);
        }

	/* Assemble the headers... */
	assemble_hw_header (interface, (unsigned char *)hw, &hbufp, hto);
	assemble_udp_ip_header (interface,
				(unsigned char *)ip, &ibufp, from.s_addr,
				to -> sin_addr.s_addr, to -> sin_port,
				(unsigned char *)raw, len);

	/* Build iovec of packet to send */
	iov [0].iov_base = ((char *)hw);
	iov [0].iov_len = hbufp;
	iov [1].iov_base = ((char *)ip);
	iov [1].iov_len = ibufp;
	iov [2].iov_base = (char *)raw;
	iov [2].iov_len = len;

	result = writev(interface -> wfdesc, iov, 3);
	if (result < 0) {
            log_error ("send_packet: interface %s: %m", interface->name);
        }
	return result;
}
#endif /* USE_NDD_SEND */

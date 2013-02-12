// dnsscrape: scrape live pcap capture for DNS requests
//
// Copyright (c) 2013 Matt Banack <matt@banack.net>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <assert.h>

#include "debug.h"
#include "dns_types.h"

void scrape_loop(pcap_t *capdev) {
    int cont = 1;
    const u_char *pkt;
    struct pcap_pkthdr hdr;
    struct packet p;
    struct dnsheader dhead;
    struct dnsheader *dh = &dhead;
    uint32_t internal_packet_no = 0;
    while(cont) {
        // should be using _dispatch() or _loop()
        
        p.len = 0;
        p.pkt = NULL;
        pkt = pcap_next(capdev, &hdr);
        p.len = hdr.caplen;
        p.pkt = pkt;

        internal_packet_no++;

        if(is_udp(&p)) {
            if(p.len >= 55 && p.len <= 512) {
                parse_header(dh, &p, 42);
                if(!is_valid_header(dh)) {
                    continue;
                }
                
                // and so we are here...
                // do I want to parse them as the same?
                //
                // what do I want to log? (and in what pattern, ie what can be dropped)
                // Q type name              (#)
                // R qname type name/IP/TXT (#)
                //
                // so realistically I can read the counts, parse all the sections
                //   print/store it, and I don't care if it's a query or response
                // well, no... I don't want to double log the query inside of the
                //   response... but I could at least parse them all and then
                //   decide what to keep or throw away
                // if any parsing fails, drop it altogether, it's probably
                //   something that just *looks* like DNS ;)

                if(dh->qdcount > 4 || dh->ancount > 20 || dh->nscount > 4 || dh->arcount > 4) {
                    fprintf(stderr, "Insane counts (%d %d %d %d)\n",
                            dh->qdcount, dh->ancount, dh->nscount, dh->arcount);
                    continue;
                }

                DEBUG_MF("\n");
                printf("  Starting parse #%d for counts (%d %d %d %d)\n",
                        internal_packet_no,
                        dh->qdcount, dh->ancount, dh->nscount, dh->arcount);

                int fail = 0;

                int next_idx = 54;
                struct qsection *qroot = NULL;
                struct qsection *qtail = NULL;
                for(int i = 0; i < dh->qdcount; i++) {
                    if(!append_qsection(&p, dh, &qtail, &next_idx)) {
                        // parsing failure, bail out
                        fail = 1;
                        break;
                    }
                    if(!qtail) {
                        fprintf(stderr, "append_qsection silently failed\n");
                    } else {
                        if(!qroot) {
                            qroot = qtail;
                        } else {
                            qtail = qtail->next;
                        }
                    }
                }
                if(fail) {
                    free_qsection(qroot);
                    continue;
                }

                struct rsection *rroot = NULL;
                struct rsection *rtail = NULL;
                for(int i = 0; i < dh->ancount; i++) {
                    if(!append_rsection(&p, dh, 1, &rtail, &next_idx)) {
                        fail = 1;
                        break;
                    }
                    if(!rtail) {
                        fprintf(stderr, "append_rsection silently failed\n");
                    } else {
                        if(!rroot) {
                            rroot = rtail;
                        } else {
                            rtail = rtail->next;
                        }
                    }
                }
                if(fail) {
                    free_qsection(qroot);
                    free_rsection(rroot);
                    continue;
                }

                for(int i = 0; i < dh->nscount; i++) {
                    if(!append_rsection(&p, dh, 2, &rtail, &next_idx)) {
                        fail = 1;
                        break;
                    }
                    if(!rtail) {
                        fprintf(stderr, "append_rsection silently failed\n");
                    } else {
                        if(!rroot) {
                            rroot = rtail;
                        } else {
                            rtail = rtail->next;
                        }
                    }
                }
                if(fail) {
                    free_qsection(qroot);
                    free_rsection(rroot);
                    continue;
                }

                for(int i = 0; i < dh->arcount; i++) {
                    if(!append_rsection(&p, dh, 3, &rtail, &next_idx)) {
                        fail = 1;
                        break;
                    }
                    if(!rtail) {
                        fprintf(stderr, "append_rsection silently failed\n");
                    } else {
                        if(!rroot) {
                            rroot = rtail;
                        } else {
                            rtail = rtail->next;
                        }
                    }
                }
                if(fail) {
                    free_qsection(qroot);
                    free_rsection(rroot);
                    continue;
                }

                // Passed all parsing
                /*
                printf("Successful parse #%d for counts (%d %d %d %d)\n",
                        internal_packet_no,
                        dh->qdcount, dh->ancount, dh->nscount, dh->arcount);
                */

                struct qsection *qtrav = qroot;
                while(qtrav) {
                    if(rroot) {
                        // visually show that this is part of a response
                        printf("  ");
                    }
                    printf("-> %s %s\n", qtype_str(qtrav->qtype), qtrav->qname);
                    qtrav = qtrav->next;
                }

                struct rsection *rtrav = rroot;
                while(rtrav) {
                    printf("<- %s %s\n", rrtype_str(rtrav->rrtype), rtrav->result);
                    rtrav = rtrav->next;
                }

                free_qsection(qroot);
                free_rsection(rroot);
            }
        }
    }
}

const char DEFAULT_IFNAME[] = "";

int main(int argc, char *argv[]) {
    int opt;
    int ifnd;
    char* ifname;
    while((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            ifnd = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -i iface\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(!ifnd) {
        printf("Using default device \"any\"... override with \"-i ifname\"\n");
        // pcap_create will use "any" if given "", so default to that
        ifname = &DEFAULT_IFNAME;
    }

    printf("Using interface %s\n", ifname);

    char ebuf[1024];
    pcap_t *capdev = pcap_create(ifname, ebuf);
    int act_ret = pcap_activate(capdev);

    if(!!act_ret) {
        fprintf(stderr, "Could not activate capture device (%d).  Sorry!\n", act_ret);
        return act_ret;
    }

    // set options on capdev ?
    //    snaplen, promisc/monitor, timeout, buffer_size, timestamp type
    pcap_set_promisc(capdev, 1);
    pcap_set_buffer_size(capdev, 1024);

    //pcap_setfilter(capdev, ?????); // have option to set just port 53 :)
    // but it is *really nice* to be able to sniff dns on non-53 ports
    scrape_loop(capdev);

    pcap_close(capdev);
    return 0;
}


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

#include "dns_types.h"

void debug_enum_devs() {
    char errbuf[1024];
    pcap_if_t *alldevsp;
    int ret = pcap_findalldevs(&alldevsp, errbuf);

    if(ret) {
        fprintf(stderr, "%d %s\n", ret, errbuf);
        return;
    }

    printf("%p\n", (void*)&alldevsp);

    if(!alldevsp) {
        fprintf(stderr, "No devices available for capture... are you root?\n");
        pcap_freealldevs(alldevsp);
        return;
    }

    // pcap_if (pcap_if_t) has:
    //     pcap_if *next
    //     char *name
    //     char *description
    //     pcap_addr *addresses
    //     bpf_u_int32 flags

    pcap_if_t *curif = alldevsp;
    while(curif) {
        printf("[%s] %s %x\n", curif->name, curif->description, curif->flags);
        pcap_addr_t *addrwalk = curif->addresses;
        while(addrwalk) {
            /*struct sockaddr_in *addr = addrwalk->addr;
            struct in_addr i_a = addr->sin_addr;
            uint32_t ip = i_a.s_addr;*/
            struct sockaddr *s_a = addrwalk->addr;
            char dst[1024];
            printf("    %s\n", inet_ntop(s_a->sa_family, s_a->sa_data, dst, 1024));
            addrwalk = addrwalk->next;
        }
        curif = curif->next;
    }

    pcap_freealldevs(alldevsp);
}

void print_query_name(const u_char *pkt, int start_idx, int pkt_len) {
    // quick n dirty!
    char *buf = malloc(sizeof(char) * (pkt_len - start_idx + 1));
    strncpy(buf, (const char *)(pkt + start_idx), pkt_len - start_idx);
    buf[pkt_len - start_idx] = 0;
    printf("[%d] %s\n", pkt_len - start_idx, buf);
    for(int i=0; i<pkt_len-start_idx; i++) {
        printf("%x ", pkt[start_idx+i]);
    }
    printf("\n");
    free(buf);
}

struct rr* get_answers(struct dnspacket *p, int header_idx, int an_start_idx, int caplen, int *parsed_an) {
    const uint8_t *pkt = p->pkt;
    struct rr *root = malloc(sizeof(struct rr));
    init_rr(root);
    struct rr *trav = root;
    int cont = 1;
    while(cont) {
        if(an_start_idx > caplen) {
            fprintf(stderr, "an_start_idx > caplen in get_answers for %d %d\n", an_start_idx, caplen);
            return root;
        }
        cont++;
        trav->next = NULL;
        int next_idx = an_start_idx;
        // this is somewhat of an abuse of parse_qsection...
        //   but for now they do the exact same thing, so *shrug*
        struct qsection *qs = parse_qsection(p, next_idx, &next_idx);

        if(qs && qs->qname) {
            *parsed_an += 1;
            trav->name = malloc(sizeof(char) * 256);
            strncpy(trav->name, qs->qname, 255);
            trav->name[255] = 0;

            trav->name_len = strlen(qs->qname);
            trav->type = qs->qtype;
            trav->rrclass = qs->qclass;
            trav->ttl = parse_u32(pkt, next_idx, next_idx+3);
            trav->rdlength = parse_u16(pkt, next_idx+4, next_idx+5);
            trav->rdata = rdata_str(pkt, trav->type, next_idx+6, trav->rdlength);
            printf("rdata is %s\n", trav->rdata);

            an_start_idx = next_idx+10 + trav->rdlength + 1;
            free_qsection(qs);
            if(next_idx >= p->len) {
                return root;
            }
            trav->next = malloc(sizeof(struct rr));
            trav = trav->next;
            init_rr(trav);
        } else {
            fprintf(stderr, "parse_qsection failed for get_answers an_start_idx=%d\n", an_start_idx);
            cont = 0;
        }

        if(cont > 5) {
            fprintf(stderr, "{!!} run-away get_answers\n");
            return root;
        }
    }
    return root;
}

void scrape_loop(pcap_t *capdev) {
    int cont = 1;
    const u_char *pkt;
    struct pcap_pkthdr hdr;
    struct dnspacket p;
    uint32_t internal_packet_no;
    while(cont) {
        // should be using _dispatch() or _loop()
        
        pkt = pcap_next(capdev, &hdr);
        p.len = hdr.caplen;
        p.pkt = pkt;

        internal_packet_no++;
        

        // TODO: currently I am assuming that this is a UDP packet.
        //   it should work with just offset tweaking for TCP
        //   but TCP DNS is probably rare enough to just ignore?
        // ethernet/ip/udp header is 42 bytes
        // dns header is 12 bytes
        if(hdr.caplen >= 55 && hdr.caplen <= 512) {
            // this is long enough to be a DNS packet
            // but short enough to still be a UDP DNS packet (limit 512b)
            p.src_port = parse_u16(pkt, 34, 35);
            p.dst_port = parse_u16(pkt, 36, 37);
            p.udp_len = parse_u16(pkt, 38, 39);
            p.udp_chksum = parse_u16(pkt, 40, 41);
            //printf("%d -> %d [%d] {%d}\n", src_port, dst_port, udp_len, udp_chksum);
            fill_dnsheader(&p, 42);
            struct dnsheader *dh = &(p.dh);
            if(is_valid_header(dh)) {
                fprintf(stderr, "[%d] ", internal_packet_no);
                if(dh->qr) { //response
                    printf("RESPONSE ");
                    int parsed_an = 0;
                    struct rr *answers;
                    if(dh->qdcount == 0) {
                        answers = get_answers(&p, 42, 54, hdr.caplen, &parsed_an);
                    } else {
                        int next_idx = 54;
                        printf(" qdcount=%d ", dh->qdcount);
                        for(int i = 0; i < dh->qdcount && i < 256; i++) {
                            // TODO: make a skip_qsection that just gives next_idx and saves overhead
                            fprintf(stderr, "{%d} ", i);
                            struct qsection *qs = parse_qsection(&p, next_idx, &next_idx);
                            free_qsection(qs);
                            if(next_idx == p.len) {
                                fprintf(stderr, "parse_qsection went over the end\n");
                                break;
                            }
                        }
                        answers = get_answers(&p, 42, next_idx, hdr.caplen, &parsed_an);
                    }
                    if(answers) {
                        if(dh->ancount != parsed_an) {
                            fprintf(stderr, "an != parsed_an for %d, %d\n",
                                    dh->ancount, parsed_an);
                        } else {
                            struct rr *trav = answers;
                            while(trav) {
                                if(trav->rdata) {
                                    if(trav->name) {
                                        printf("%s", trav->name);
                                    }
                                    printf(" [%d %d %d %d] ", trav->type, trav->rrclass, trav->ttl, trav->rdlength);
                                    if(trav->rdata) {
                                        printf("%s", trav->rdata);
                                    }
                                    printf("\n");
                                } else {
                                    fprintf(stderr, "trav->rdata NULL\n");
                                }
                                trav = trav->next;
                            }
                        }
                        free_rr(answers);
                    } else {
                        fprintf(stderr, "answers is null\n");
                    }
                } else { // query
                    printf("QUERY ");
                    if(dh->qdcount > 0) {
                        int next_idx = 54;
                        for(int i=0; i<dh->qdcount; i++) {
                            struct qsection *qs = parse_qsection(&p, next_idx, &next_idx);
                            if(!qs) {
                                break;
                            }
                            if(qs->qname) {
                                printf("%s %s\n", qtype_str(qs->qtype), qs->qname);
                            }
                            free_qsection(qs);
                            if(next_idx == p.len) {
                                fprintf(stderr, "parse_qsection went over the end\n");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

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
        ifname = malloc(sizeof(char) * 1);
        ifname[0] = 0;
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

    //pcap_setfilter(capdev, ?????); // set just port 53 :)
    scrape_loop(capdev);

    pcap_close(capdev);
    return 0;
}

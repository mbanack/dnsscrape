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

void debug_enum_devs() {
    fprintf(stderr, "\nPrinting all devices for you:\n\n");
    char errbuf[1024];
    pcap_if_t *alldevsp;
    int ret = pcap_findalldevs(&alldevsp, errbuf);

    if(ret) {
        fprintf(stderr, "%d %s\n", ret, errbuf);
        return;
    }


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
            if(s_a) {
                const char *ret;
                char dst[1024];
                ret = inet_ntop(s_a->sa_family, s_a->sa_data, dst, 1024);
                if(ret) {
                    printf("    %s\n", ret);
                }
            }
            addrwalk = addrwalk->next;
        }
        curif = curif->next;
    }

    pcap_freealldevs(alldevsp);
}

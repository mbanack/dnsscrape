// dnsscrape: scrape live pcap capture for DNS requests
//   dns_types.c: functions to juggle structs
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "dns_types.h"

// for now this will only work for a 2-byte int... but obviously
//   this should be generalized to 4 ;)
uint32_t parse_u32(const uint8_t *pkt, int start_idx, int end_idx) {
    assert(start_idx <= end_idx);
    uint32_t ret = 0;
    for(int i=start_idx; i<=end_idx; i++) {
        ret |= pkt[i];
        if(i != end_idx) {
            ret = ret << 8;
        }
    }
    return ret;
}

uint16_t parse_u16(const uint8_t *pkt, int start_idx, int end_idx) {
    return (pkt[start_idx] << 8) | pkt[end_idx];
}

uint8_t* parse_rdata(const uint8_t *pkt, uint16_t type, int start_idx, uint16_t len) {
    int name_len = 0;
    int next_idx = 0;
    switch(type) {
    case 1: // A
        printf("A");
        break;
    case 5: // CNAME
        printf("CNAME");
        return (uint8_t*) get_query_name(pkt, start_idx, start_idx+len, &name_len, &next_idx);
        break;
    case 12: // PTR
        printf("PTR");
        break;
    case 16: // TXT
        printf("TXT");
        break;
    default:
        fprintf(stderr, "Response type %d is not supported\n", type);
        break;
    }


    return NULL;
}

// parse dns header from packet.
// pkt should be a pointer to a suspected dns packet with header
//   starting at start_idx
// pkt should be at least start_idx + 12b long
// returned dnsheader to be freed by caller
struct dnsheader* parse_header(const uint8_t *pkt, int start_idx) {
    struct dnsheader *dh = malloc(sizeof(struct dnsheader));

    dh->id = parse_u16(pkt, start_idx, start_idx+1);
    uint8_t b = pkt[start_idx+2];
    dh->qr = b >> 7;
    dh->opcode = (b & 0x78) >> 3;
    dh->aa = (b & 0x4) >> 2;
    dh->tc = (b & 0x2) >> 1;
    dh->rd = (b & 0x1);
    b = pkt[start_idx+3];
    dh->ra = b >> 7;
    dh->z = (b & 0x70) >> 4;
    dh->rcode = (b & 0xF);
    dh->qdcount = parse_u16(pkt, start_idx+4, start_idx+5);
    dh->ancount = parse_u16(pkt, start_idx+6, start_idx+7);
    dh->nscount = parse_u16(pkt, start_idx+8, start_idx+9);
    dh->arcount = parse_u16(pkt, start_idx+10, start_idx+11);

    return dh;
}

// this is based on a cursory reading of rfc1035
// it may pass for some strange invalid header
// also, for my purposes I may consider a technically valid
// header invalid simply to reduce further processing overhead
// ie I don't care about a query or response with a 0 count
int is_valid_header(struct dnsheader *h) {
    if(h->z != 0) {
        return 0;
    }
    if(h->opcode > 2) {
        return 0;
    }
    if(h->tc) {
        fprintf(stderr, "DNS message truncated... this could cause problems.\n");
    }
    if(h->rcode > 5) {
        return 0;
    }

    if(h->qr) { // response
        if(h->rcode != 0) {
            return 0;
        }
        if(h->ancount == 0) {
            return 0;
        }
        if(h->qdcount != 0) {
            // TODO: this is wrong.
            //   my in-the-wild queries are returning the query
            //   as part of the response (I guess to match them up easier)
            // .. so return 1, but also need to fix the response parsing
            //   code because it assumes a 0-length question section
            return 0;
        }
        return 1;
    } else { // query
        if(h->qdcount == 0) {
            return 0;
        }
        if(h->ancount != 0) {
            return 0;
        }
        if(h->nscount != 0) {
            return 0;
        }
        if(h->arcount != 0) {
            return 0;
        }
        return 1;
    }
}

// get the first query name (can be many, we ignore all but first)
// returend string to be freed by caller
char* get_query_name(const u_char *pkt, int start_idx, int pkt_len, int *ret_len, int *next_idx) {
    int buf_len = 1024;
    char *buf = malloc(sizeof(char) * buf_len);
    int buf_idx = 0;
    int idx = start_idx;
    while(idx < pkt_len) {
        u_char chunklen = pkt[idx];
        if(chunklen == 0) {
            // end of labels
            break;
        }
        if(idx + chunklen >= pkt_len) {
            fprintf(stderr, "Error parsing query name: bad label length\n");
            free(buf);
            return NULL;
        }
        if(buf_idx + chunklen >= buf_len) {
            fprintf(stderr, "Query name too long");
            free(buf);
            return NULL;
        }

        if((chunklen & 0xC0) == 0xC0) { // label pointer
            uint16_t offset = 0x3FFF & parse_u16(pkt, idx, idx+1);
            int subname_len = 0;
            int subname_next_idx = 0;
            char *subname = get_query_name(pkt, start_idx + offset, pkt_len, &subname_len, &subname_next_idx);
            if(subname) {
                if(buf_idx + subname_len >= buf_len) {
                    fprintf(stderr, "Query name too long");
                    free(buf);
                    return NULL;
                }
                strncpy(buf+buf_idx, subname, subname_len);
                buf_idx += subname_len;
                buf[buf_idx] = '.';
                buf_idx += 1;
                idx += 2;
                free(subname);
            }
        } else {
            strncpy(buf+buf_idx, (const char *)pkt+idx+1, chunklen);
            idx += chunklen + 1;
            buf_idx += chunklen;
            buf[buf_idx] = '.';
            buf_idx += 1;
        }
    }
    buf[buf_idx] = 0;
    *ret_len = buf_idx - 1;
    if(buf_idx - 1 >= 0) {
        if(buf[buf_idx-1] == '.') {
            buf[buf_idx-1] = 0;
            *ret_len = buf_idx - 2;
        }
    }
    *next_idx = idx;
    return buf;
}

// dnsscrape: scrape live pcap capture for DNS requests
//   dns_types.h: struct/type definitions
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

#ifndef DNSTYPES_H
#define DNSTYPES_H

uint32_t parse_u32(const uint8_t *pkt, int start_idx, int end_idx);
uint16_t parse_u16(const uint8_t *pkt, int start_idx, int end_idx);
struct dnsheader* parse_header(const uint8_t *pkt, int start_idx);
int is_valid_header(struct dnsheader *h);
uint8_t *parse_rdata(const uint8_t *pkt, uint16_t type, int start_idx, uint16_t len);
char* get_query_name(const u_char *pkt, int start_idx, int pkt_len, int *ret_len, int *next_idx);

struct dnsheader {
    uint16_t id;
    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t z;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// resource record
struct rr {
    struct rr *next;
    int name_len;
    char *name;
    uint16_t type;
    uint16_t rrclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
};

#endif

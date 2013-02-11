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

// qtype id to name mappings
extern const char QT_UNKNOWN[];
extern const char QT_A[];
extern const char QT_NS[];
extern const char QT_MD[];
extern const char QT_MF[];
extern const char QT_CNAME[];
extern const char QT_SOA[];
extern const char QT_MB[];
extern const char QT_MG[];
extern const char QT_MR[];
extern const char QT_NULL[];
extern const char QT_WKS[];
extern const char QT_PTR[];
extern const char QT_HINFO[];
extern const char QT_MINFO[];
extern const char QT_MX[];
extern const char QT_TXT[];
extern const char *QT_NAMES[];
extern const char QT_AXFR[];
extern const char QT_MAILB[];
extern const char QT_MAILA[];
extern const char QT_WILD[];
extern const char QT_AAAA[];
extern const char QT_SRV[];

struct dnsheader {
    unsigned int pkt_idx;
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

struct packet {
    uint32_t len;
    const uint8_t *pkt;
}

int is_udp(struct packet);

struct qsection {
    struct qsection *next;
    // dynamically allocated, human-readable name (ie not usable as a label ptr)
    //   max length of qname is 255 bytes... bound all prints and buffer copies
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
};

void free_qsection(struct qsection *q);

const char* qtype_str(uint16_t qtype);
const char* rtype_str(uint16_t rtype) {
int append_qsection(struct packet *p, struct dnsheader *dh, \
        struct qsection *qtail, int *next_idx);
int append_name(char *str, int str_pos, const u_char *pkt, int pkt_idx);
int append_label(char *str, int str_pos, const u_char *pkt, int pkt_idx);

struct rsection {
    struct rsection *next;
    struct qsection *assoc_query; // or just have the qname, but then I have to
                                  // decide whether to copy or just point to it
    int rtype; // 1 -> an, 2 -> ns, 3 -> ar
    // dynamically allocated, human-readable result
    char *result;
    int result_len;
};

void free_rsection(struct rsection *r);
int append_rsection(struct packet *p, struct dnsheader *dh, \
        struct rsection *rtail, int *next_idx);

uint32_t parse_u32(const uint8_t *pkt, int start_idx, int end_idx);
uint16_t parse_u16(const uint8_t *pkt, int start_idx, int end_idx);
struct dnsheader* parse_header(const uint8_t *pkt, int start_idx);
int is_valid_header(struct dnsheader *h);
char* rdata_str(const uint8_t *pkt, uint16_t type, int start_idx, uint16_t len);
char* get_query_name(const u_char *pkt, int start_idx, int pkt_len, \
        int *ret_len, int *next_idx);

#endif

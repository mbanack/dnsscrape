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

const char QT_UNKNOWN[] = "?";
const char QT_A[] = "A";
const char QT_NS[] = "NS";
const char QT_MD[] = "MD";
const char QT_MF[] = "MF";
const char QT_CNAME[] = "CNAME";
const char QT_SOA[] = "SOA";
const char QT_MB[] = "MB";
const char QT_MG[] = "MG";
const char QT_MR[] = "MR";
const char QT_NULL[] = "NULL";
const char QT_WKS[] = "WKS";
const char QT_PTR[] = "PTR";
const char QT_HINFO[] = "HINFO";
const char QT_MINFO[] = "MINFO";
const char QT_MX[] = "MX";
const char QT_TXT[] = "TXT";
const char *QT_NAMES[] = {QT_UNKNOWN, QT_A, QT_NS, QT_MD, QT_MF, QT_CNAME, QT_SOA, QT_MB, QT_MG, QT_MR, QT_NULL, QT_WKS, QT_PTR, QT_HINFO, QT_MINFO, QT_MX, QT_TXT};
const char QT_AXFR[] = "AXFR";
const char QT_MAILB[] = "MAILB";
const char QT_MAILA[] = "MAILA";
const char QT_WILD[] = "*";
const char QT_AAAA[] = "AAAA";
const char QT_SRV[] = "SRV";

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

char* rdata_str(const uint8_t *pkt, uint16_t type, int start_idx, uint16_t len) {
    int name_len = 0;
    int next_idx = 0;
    switch(type) {
    case 0: // ????
        fprintf(stderr, "rdata type 0... skipping\n");
        break;
    case 1: // A
        printf("A ");
        uint32_t addr = parse_u32(pkt, start_idx, start_idx+3);
        printf("shortcut: addr is %x\n", addr);
        return NULL;
        break;
    case 5: // CNAME
        printf("CNAME ");
        // TODO: parse_label ??
        break;
    case 12: // PTR
        printf("PTR ");
        break;
    case 16: // TXT
        printf("TXT ");
        break;
    default:
        fprintf(stderr, "Response type %d is not supported\n", type);
        break;
    }

    return NULL;
}

struct dnsheader* parse_header(struct packet *p, int start_idx) {
    const uint8_t *pkt = p->pkt;
    struct dnsheader *dh = malloc(sizeof(struct dnsheader));

    dh->pkt_idx = start_idx;
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
        if(h->qdcount == 0) {
            fprintf(stderr, "Parsing response with 0 QDs... trying anyways (counts %d %d %d %d)\n", h->qdcount, h->ancount, h->nscount, h->arcount);
        }
        if(h->tc) {
            fprintf(stderr, "DNS message truncated... this could cause problems.\n");
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
        if(h->tc) {
            fprintf(stderr, "DNS message truncated... this could cause problems.\n");
        }
        return 1;
    }
}

void init_rr(struct rr *r) {
    r->next = NULL;
    r->name_len = 0;
    r->name = NULL;
    r->type = 0;
    r->rrclass = 0;
    r->ttl = 0;
    r->rdlength = 0;
    r->rdata = NULL;
}

void free_rr(struct rr *r) {
    struct rr *next;
    while(r) {
        next = r->next;
        if(r->name) {
            free(r->name);
        }
        if(r->rdata) {
            free(r->rdata);
        }
        free(r);
        r = next;
    }
}

// arg next_idx is the index of the first byte of the section to parse
// return 0 on any parsing error
// otherwise append the newly parsed qsection to qtail
// next_idx points to the byte after this section
int append_qsection(struct packet *p, struct dnsheader *dh, struct qsection *qtail,
                    int *next_idx) {
    struct qsection *build = malloc(sizeof(struct qsection));
    build->qname = malloc(sizeof(uint8_t) * 256);
    build->qtype = 0xFFFF;
    build->qclass = 0xFFFF;
    int qname_len = 0;
    const uint8_t *pkt = p->pkt;
    uint32_t runaway = 0;
    while(*next_idx < p->len) {
        uint8_t chunklen = pkt[*next_idx];
        if(chunklen == 0) { // end of name
            build->qtype = parse_u16(pkt, (*next_idx)+1, (*next_idx)+2);
            build->qclass = parse_u16(pkt, (*next_idx)+3, (*next_idx)+4);
            build->qname[255] = 0;
            *next_idx = (*next_idx) + 5;
            qtail->next = build;
            return 1;
        }
        if((chunklen & 0xC0) == 0xC0) { // label pointer
            uint16_t offset = 0x3FFF & parse_u16(pkt, (*next_idx), (*next_idx)+1);
            if(p->dh.pkt_idx + offset >= p->len) {
                break;
            }
            int label_len = append_name(build->qname, &qname_len, pkt, dh->pkt_idx + offset);
            if(label_len <= 0) {
                break;
            }
            build->qtype = parse_u16(pkt, (*next_idx)+1, (*next_idx)+2);
            build->qclass = parse_u16(pkt, (*next_idx)+3, (*next_idx)+4);
            build->qname[255] = 0;
            *next_idx = (*next_idx) + 5;
            qtail->next = build;
            return 1;
        } else { // regular label
            int label_len = append_label(build->qname, &qname_len, pkt, *next_idx);
            if(label_len <= 0) {
                break;
            }
            next_idx += label_len;
        }
        if(runaway++ > 12) {
            break;
        }
    }
    
    // abnormal exit (parse error etc)
    free_qsection(build);
    return 0;
}

// str is string to append to (hard limit of 256 length including null byte)
// str_pos is next available position
// pkt_idx points to the label length byte (followed by label of that length)
// returns the number of bytes appended (label length + 1)
//   advancing the external pkt_idx by that amount will put you at the next length byte
int append_label(char *str, int str_pos, const u_char *pkt, int pkt_idx) {
    uint8_t chunklen = pkt[pkt_idx];
    if(chunklen > 63) {
        return -1;
    }
    if(str_pos + chunklen > 255) { // allow to chop off last .
        return -1;
    }
    strncpy(str + str_pos, (char*)&pkt[pkt_idx+1], chunklen);
    str[str_pos + chunklen] = '.';
    return chunklen + 1;
}

// same semantics as append_label, but
// get the entire name (series of labels ending in a zero byte)
// my reading of rfc1035 is that recursive pointers may be allowed, but
// I am not going to support them... if this hits a pointer it will throw
// up its hands
int append_name(char *str, int str_pos, const u_char *pkt, int pkt_idx) {
    uint8_t chunklen = pkt[pkt_idx];
    int num_appended = 0;
    while(chunklen != 0) {
        if((chunklen & 0xC0) != 0) {
            return -1;
        }
        if(str_pos + num_appended > 256) { // allow to chop off last .
            return -1;
        }
        int a = append_label(str, str_pos + num_appended, pkt, pkt_idx + num_appended);
        if(a < 0) {
            return -1;
        }
        num_appended += a;
    }
    return num_appended;
}

int append_rsection(struct packet *p, struct dnsheader *dh, struct rsection *rtail, \
                    int *next_idx) {
    // STUB
}

void free_qsection(struct qsection *q) {
    struct qsection *next;
    while(q) {
        next = q->next;
        if(q->qname) {
            free(q->qname);
        }
        free(q);
        q = next;
    }
}

void free_rsection(struct rsection *r) {
    struct rsection *next);
    while(r) {
        next = r->next;
        if(r->result) {
            free(r->result);
        }
        free(r);
        r = next;
    }
}

const char* qtype_str(uint16_t qtype) {
    if(qtype < 17) {
        return QT_NAMES[qtype];
    }
    switch(qtype) {
    case 252:
        return (const char*)&QT_AXFR;
    case 253:
        return (const char*)&QT_MAILB;
    case 254:
        return (const char*)&QT_MAILA;
    case 255:
        return (const char*)&QT_WILD;
    case 28:
        return (const char*)&QT_AAAA;
    case 33: // MDNS
        return (const char*)&QT_SRV;
    default:
        fprintf(stderr, "unknown query type %d\n", qtype);
        return (const char*)&QT_UNKNOWN;
    }
}

// RR types are a subset of Q types
const char* rtype_str(uint16_t rtype) {
    if(rtype < 17) {
        return QT_NAMES[rtype];
    }
    fprintf(stderr, "unknown response type %d\n", rtype);
    return (const char*)&QT_UNKNOWN;
}

int is_udp(struct packet *p) {
    if(p->len < 42) {
        return 0;
    }
    return p->pkt[0x17] == 17;
}

int is_tcp(struct packet *p) {
    if(p->len < 42) {
        return 0;
    }
    return p->pkt[0x17] == 6;
}


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
        return get_query_name(pkt, start_idx, start_idx+len, &name_len, &next_idx);
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

// parse dns header from packet.
// pkt should be a pointer to a suspected dns packet with header
//   starting at start_idx
// pkt should be at least start_idx + 12b long
// returned dnsheader to be freed by caller
struct dnsheader* parse_header(const uint8_t *pkt, int start_idx) {
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

// get the first query name (can be many, we ignore all but first)
// returend string to be freed by caller
char* get_query_name(const u_char *pkt, int start_idx, int pkt_len, int *ret_len, int *next_idx) {
    int buf_len = 1024;
    char *buf = malloc(sizeof(char) * buf_len);
    int buf_idx = 0;
    int idx = start_idx;
    while(idx < pkt_len - 2) { // stop 2 bytes before end for just the name
        u_char chunklen = pkt[idx];
        if(chunklen == 0) {
            // end of labels
            break;
        }

        if((chunklen & 0xC0) == 0xC0) { // label pointer
            uint16_t offset = 0x3FFF & parse_u16(pkt, idx, idx+1);
            if(start_idx + offset >= pkt_len) {
                fprintf(stderr, "Label pointer outside packet. Stop.\n");
                free(buf);
                return NULL;
            }
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
            if(idx + chunklen >= pkt_len) {
                fprintf(stderr, "Error parsing query name: bad label length %d\n", chunklen);
                free(buf);
                return NULL;
            }
            if(buf_idx + chunklen >= buf_len) {
                fprintf(stderr, "Query name too long");
                free(buf);
                return NULL;
            }
            
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

void init_rr(struct rr *r) {
    r->next = NULL;
    r->name_len = 0;
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
        if(r->next) {
            free(r->next);
        }
        if(r->rdata) {
            free(r->rdata);
        }
        free(r);
        r = next;
    }
}

// return parsed qsection with human-readable name
//   *next_idx contains the index of the next section or past p->len for "done"
struct qsection* parse_qsection(struct packet *p, struct dnsheader *h,
                                int qs_idx, int *next_idx) {
    struct qsection *build = malloc(sizeof(struct qsection));
    build->qname = malloc(sizeof(uint8_t) * 256);
    build->qtype = 0xFFFF;
    build->qclass = 0xFFFF;
    int qname_len = 0;
    unsigned int idx = qs_idx;
    const uint8_t *pkt = p->pkt;
    while(idx < p->len) {
        uint8_t chunklen = pkt[idx];
        if(chunklen == 0) {
            // end of labels
            build->qtype = parse_u16(pkt, idx+1, idx+2);
            build->qclass = parse_u16(pkt, idx+3, idx+4);
            *next_idx = idx + 5;
            return build;
        }
        if((chunklen & 0xC0) == 0xC0) { // label pointer
            uint16_t offset = 0x3FFF & parse_u16(pkt, idx, idx+1);
            if(h->pkt_idx + offset >= p->len) {
                fprintf(stderr, "Label pointer outside packet. Stop.\n");
                *next_idx = idx + 2;
                return build;
            }
            unsigned int ptr_idx = h->pkt_idx + offset;
            uint8_t ptr_chunklen = pkt[ptr_idx];
            while(ptr_idx < p->len && ptr_chunklen > 0) {
                if((ptr_chunklen & 0xC0) != 0) {
                    fprintf(stderr, "Recursive label pointer. Stop.\n");
                    break;
                }
                strncpy(build->qname + qname_len, (char*)&pkt[ptr_idx+1],
                        ptr_chunklen);
                qname_len += ptr_chunklen;
                build->qname[qname_len] = '.';
                qname_len += 1;
                if(qname_len > 255) {
                    fprintf(stderr, "qname length > 255, capping with \\0\n");
                    build->qname[255] = 0;
                }
                ptr_idx += 1 + ptr_chunklen;
            }
            idx += 2;
        } else { // regular qname
            if(chunklen > 63) {
                fprintf(stderr, "Non-pointer chunk length >63. Stop.\n");
                break;
            }
            strncpy(build->qname + qname_len, (char*)&pkt[idx+1],
                    chunklen);
            qname_len += chunklen;
            build->qname[qname_len] = '.';
            qname_len += 1;
            if(qname_len > 255) {
                fprintf(stderr, "qname length > 255, capping with \\0\n");
                build->qname[255] = 0;
            }
            idx += 1 + chunklen;
        }
    }
    
    fprintf(stderr, "parse_qsection overran packet\n");
    *next_idx = p->len;
    return build;
}

void free_qsection(struct qsection *q) {
    if(q) {
        if(q->qname) {
            free(q->qname);
        }
        free(q);
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


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
#include <arpa/inet.h>

#include "dns_types.h"
#include "debug.h"

#define SHOW_NO_QD_WARNING (0)
#define MAX_LABELS (100)

// dynamic memory counts
int memct_qsec = 0;
int memct_rsec = 0;
int memct_str = 0;

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
const char QT_NSEC[] = "NSEC";

// grab 4 bytes starting at start_idx, parse as uint32
//   pkt length must be >= start_idx + 4
uint32_t parse_u32(const uint8_t *pkt, int start_idx) {
    return (pkt[start_idx] << 24) 
        | (pkt[start_idx + 1] << 16)
        | (pkt[start_idx + 2] << 8)
        | (pkt[start_idx + 3]);
}

// grab 2 bytes starting at start_idx, parse as uint16
//   pkt length must be >= start_idx + 3
uint16_t parse_u16(const uint8_t *pkt, int start_idx) {
    return (pkt[start_idx] << 8) | pkt[start_idx + 1];
}

// parse_ipheader makes no attempt to validate the data
//   and p->pkt must be predetermined to have minimum length
void parse_ipheader(struct ipheader *ih, struct packet *p, int start_idx) {
    const uint8_t *pkt = p->pkt;
    ih->version = (pkt[start_idx] & 0xF0) >> 4;
    ih->header_length = pkt[start_idx] & 0x0F;
    ih->diff_services = pkt[start_idx + 1];
    ih->packet_length = parse_u16(pkt, start_idx + 2);
    ih->id = parse_u16(pkt, start_idx + 4);
    ih->flags_and_fragment_offset = parse_u16(pkt, start_idx + 6);
    ih->ttl = pkt[start_idx + 8];
    ih->protocol = pkt[start_idx + 9];
    ih->header_checksum = parse_u16(pkt, start_idx + 10);
    ih->src_ip = ntohl(parse_u32(pkt, start_idx + 12));
    ih->dst_ip = ntohl(parse_u32(pkt, start_idx + 16));
    ih->padded_options = parse_u32(pkt, start_idx + 20);
}

// parse_udpheader makes no attempt to validate the data
//   and p->pkt must be predetermined to have minimum length
void parse_udpheader(struct udpheader *uh, struct packet *p, int start_idx) {
    const uint8_t *pkt = p->pkt;
    uh->src_port = parse_u16(pkt, start_idx);
    uh->dst_port = parse_u16(pkt, start_idx + 2);

}

// parse_dnsheader makes no attempt to validate the data
//   and p->pkt must be predetermined to have minimum length
void parse_dnsheader(struct dnsheader *dh, struct packet *p, int start_idx) {
    const uint8_t *pkt = p->pkt;

    dh->pkt_idx = start_idx;
    dh->id = parse_u16(pkt, start_idx);
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
    dh->qdcount = parse_u16(pkt, start_idx+4);
    dh->ancount = parse_u16(pkt, start_idx+6);
    dh->nscount = parse_u16(pkt, start_idx+8);
    dh->arcount = parse_u16(pkt, start_idx+10);
}

// this is based on a cursory reading of rfc1035
// it may pass for some strange invalid header
// also, for my purposes I may consider a technically valid
// header invalid simply to reduce further processing overhead
// ie I don't care about a query or response with a 0 count
int is_valid_dnsheader(struct dnsheader *h) {
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
#if SHOW_NO_QD_WARNING
        if(h->qdcount == 0) {
            fprintf(stderr, "Parsing response with 0 QDs... trying anyways (counts %d %d %d %d)\n", h->qdcount, h->ancount, h->nscount, h->arcount);
        }
#endif
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

// arg next_idx is the index of the first byte of the section to parse
// return 0 on any parsing error, 1 on success
// otherwise append the newly parsed qsection to qtail
// next_idx points to the byte after this section
int append_qsection(struct packet *p, struct dnsheader *dh, \
        struct qsection **qtail, int *next_idx) {
    struct qsection *build = make_qsection();
    const uint8_t *pkt = p->pkt;

    if(parse_name(build->qname, p, dh->pkt_idx, next_idx)) {
        build->qtype = parse_u16(pkt, (*next_idx));
        build->qclass = parse_u16(pkt, (*next_idx)+2);
        build->qname[255] = 0; // paranoia!
        *next_idx += 4;

        if(!*qtail) {
            *qtail = build;
        } else {
            (*qtail)->next = build;
        }
        return 1;
    } else {
        // abnormal exit (parse error etc)
        free_qsection(build);
        return 0;
    }
}

// str should be a preallocated buffer with a size of exactly 256 bytes
// dh_start should be the index of the start of the dns header (42)
// returns 1/0 on success/failure
//   postcondition on success: idx is pointing to the byte after the name
int parse_name(char *str, struct packet *p, int dh_start, int *idx) {
    str[0] = 0; // even if we fail without touching the string, 0-cap it
    int str_pos = 0;
    uint32_t runaway = 0;
    if(*idx < 0 || dh_start < 0) {
        return 0;
    }
    while((uint32_t)*idx < p->len) {
        uint8_t chunklen = p->pkt[*idx];
        if(chunklen == 0) { // end of name
            *idx += 1;
            str[255] = 0;
            return 1;
        }
        if((chunklen & 0xC0) == 0xC0) { // label pointer
            uint16_t offset = 0x3FFF & parse_u16(p->pkt, *idx);
            if((uint32_t)dh_start + offset >= p->len) {
                fprintf(stderr, "parse_name: dh_start + offset >= p->len for (%d %d %d)\n", dh_start, offset, p->len);
                break;
            }
            int label_len = append_name(str, str_pos, p, dh_start,
                    dh_start+offset, 0);
            if(label_len <= 0) {
                fprintf(stderr,"parse_name: label_len <= 0 for pointer\n");
                break;
            }
            *idx += 2;
            str[255] = 0;
            return 1;
        } else { // regular label
            int label_len = append_label(str, str_pos, p->pkt, *idx);
            if(label_len <= 0) {
                fprintf(stderr,"parse_name: label_len <= 0 for regular label\n");
                break;
            }
            *idx += label_len;
            str_pos += label_len;
        }
        if(runaway++ > MAX_LABELS) {
            fprintf(stderr, "parse_name: runaway\n");
            break;
        }
    }

    fprintf(stderr, "parse_name overran packet\n");
    str[255] = 0; // paranoia!
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
    if(str_pos + chunklen > 254) {
        // I am chopping them off at 254 instead of 255 byte names
        //   to simplify assuring myself that I always 0-cap
        //   But really, who uses 255 byte domain names?
        return -1;
    }
    strncpy(str + str_pos, (char*)&pkt[pkt_idx+1], chunklen);
    str[str_pos + chunklen] = '.';
    str[str_pos + chunklen + 1] = 0;
    return chunklen + 1;
}

// same semantics as append_label, but
// get the entire name (series of labels ending in a zero byte)
// my reading of rfc1035 is that recursive pointers may be allowed, but
int append_name(char *str, int str_pos, struct packet *p, int dh_start, \
        int pkt_idx, int recurse_ct) {
    //fprintf(stderr, "append_name(%p, %d, %p, %d, %d, %d)\n",
    //        str, str_pos, p, dh_start, pkt_idx, recurse_ct);
    const u_char *pkt = p->pkt;
    uint8_t chunklen = pkt[pkt_idx];
    int num_appended = 0;
    if(dh_start < 0) {
        return 0;
    }
    while(chunklen != 0) {
        if((chunklen & 0xC0) != 0) {
            if((chunklen & 0xC0) != 0xC0) {
                fprintf(stderr, "invalid chunk length %x\n", chunklen);
                return -1;
            }
            uint16_t offset = 0x3FFF & parse_u16(p->pkt,
                    (pkt_idx + num_appended));
            if((uint32_t)dh_start + offset >= p->len) {
                fprintf(stderr, "parse_name: dh_start + offset >= p->len for (%d %d %d)\n", dh_start, offset, p->len);
                break;
            }

            if(recurse_ct >= 12) {
                fprintf(stderr, "append_name: runaway recursive labels\n");
                return -1;
            }
            // recursive label pointer ... *mutter*
            //fprintf(stderr, "append_name: recursive label pointer\n");
            int ct = append_name(str, str_pos + num_appended, p, dh_start,
                    dh_start + offset, recurse_ct + 1);
            if(ct < 0) {
                fprintf(stderr, "append_name: recursive append_name failed\n");
                return -1;
            }
            return num_appended + 2;
        }
        if(str_pos + num_appended > 256) { // allow to chop off last .
            fprintf(stderr, "append_name overran 256 bytes\n");
            return -1;
        }
        int a = append_label(str, str_pos + num_appended, pkt, pkt_idx + num_appended);
        if(a < 0) {
            fprintf(stderr, "append_name: append_label returned %d\n", a);
            return -1;
        }
        num_appended += a;
        chunklen = pkt[pkt_idx + num_appended];
    }
    str[str_pos + num_appended] = 0;
    return num_appended;
}

// returns 1 on success, 0 on failure (any parsing error)
int append_rsection(struct packet *p, struct dnsheader *dh, int type, \
        struct rsection **rtail, int *next_idx) {
    if(*next_idx < 0) {
        return 0;
    }
    struct rsection *build = make_rsection();
    const uint8_t *pkt = p->pkt;


    char name[256];
    // parse the name within the RR data, and just drop it
    if(!parse_name(&name[0], p, dh->pkt_idx, next_idx)) {
        // abnormal exit (parse error etc)
        fprintf(stderr, "Failed parse_name for RR name\n");
        free_rsection(build);
        return 0;
    }


    // BOUNDS CHECK: next_idx + enough for type, class, ttl, rdlength
    if((uint32_t)*next_idx + 2 + 2 + 4 + 2 >= p->len) {
        fprintf(stderr, "Failed bounds check for RR size\n");
        free_rsection(build);
        return 0;
    }

    build->type = type; // type is my classification of AN/NS/AR
    build->rrtype = parse_u16(pkt, (*next_idx)); // RR type
    // skip class and ttl of 2 and 4 bytes respectively
    *next_idx += 2 + 2 + 4;
    uint16_t rdlength = parse_u16(pkt, (*next_idx));
    *next_idx += 2;

    // BOUNDS CHECK: next_idx --> rdlength
    if((uint32_t)*next_idx + rdlength > p->len) {
        fprintf(stderr,
                "Failed bounds check for rdlength in p->len (%d+%d %d >=? %d)\n",
                *next_idx, rdlength, *next_idx + rdlength, p->len);
        free_rsection(build);
        return 0;
    }

    // now we can parse out the rdata based on the RR type
    int success = 1;
    switch(build->rrtype) {
    case 1: // A
    case 28: // AAAA
        build->result = malloc(sizeof(char) * 17);
        memct_str++;
        snprintf(build->result, 17, "%d.%d.%d.%d",
                p->pkt[*next_idx], p->pkt[(*next_idx)+1],
                p->pkt[(*next_idx)+2], p->pkt[(*next_idx)+3]);
        build->result[16] = 0;
        *next_idx += 4;
        break;
    case 2: // NS
        build->result = malloc(sizeof(char) * 256);
        memct_str++;
        if(parse_name(build->result, p, dh->pkt_idx, next_idx)) {
            success = 1;
        } else {
            success = 0;
        }
        break;
    case 5: // CNAME
        build->result = malloc(sizeof(char) * 256);
        memct_str++;
        if(parse_name(build->result, p, dh->pkt_idx, next_idx)) {
            //fprintf(stderr, "CNAME success: %s\n", build->result);
            success = 1;
        } else {
            success = 0;
        }
        break;
    case 6: {// SOA
        char mname[256];
        char rname[256];
        if(!parse_name(&mname[0], p, dh->pkt_idx, next_idx)) {
            success = 0;
            break;
        }
        if(!parse_name(&rname[0], p, dh->pkt_idx, next_idx)) {
            success = 0;
            break;
        }
        // ignore serial, refresh, retry, expire, minimum
        *next_idx += 20;
        mname[255] = 0;
        rname[255] = 0;
        uint32_t mname_len = strlen(mname);
        uint32_t rname_len = strlen(rname);
        uint32_t name_len = mname_len + rname_len;
        build->result = malloc(sizeof(char) * (name_len + 2));
        if(build->result == NULL) {
            fprintf(stderr, "malloc failed in SOA parse\n");
            success = 0;
            break;
        }
        memct_str++;
        strncpy(build->result, &mname[0], mname_len);
        build->result[mname_len] = 0x20;
        build->result[mname_len + 1] = 0x00;
        strncat(build->result, &rname[0], rname_len); // cond jump/mov depends on uninit'd values
        build->result[name_len + 1] = 0;
        success = 1;
        break; }
    case 10: // NULL
        fprintf(stderr, "Found NULL RR type... rdlength is %d\n", rdlength);
        // we already bounds checked to make sure we won't go outside pkt
        build->result = malloc(sizeof(uint8_t) * rdlength + 1);
        if(build->result == NULL) {
            success = 0;
            break;
        }
        memct_str++;
        memcpy(build->result, &(p->pkt[*next_idx]), rdlength);
        *next_idx += rdlength;
        build->result[rdlength] = 0;
        success = 1;
        break;
    case 11: // WKS
        // allow for a full-sized dotted quad plus 65536
        build->result = malloc(sizeof(uint8_t) * (16 + 6 + rdlength + 1));
        memct_str++;
        snprintf(build->result, 17 + 8, "%d.%d.%d.%d %d ",
                p->pkt[*next_idx], p->pkt[(*next_idx)+1],
                p->pkt[(*next_idx)+2], p->pkt[(*next_idx)+3],
                p->pkt[(*next_idx)+4]);
        build->result[16 + 6 + rdlength] = 0;
        *next_idx += rdlength;
        success = 1;
        break;
    case 12: // PTR
        build->result = malloc(sizeof(char) * 256);
        memct_str++;
        if(!parse_name(build->result, p, dh->pkt_idx, next_idx)) {
            success = 1;
        } else {
            success = 0;
        }
        build->result[255] = 0;
        break;
    case 13: // HINFO
        build->result = malloc(sizeof(char) * rdlength + 1);
        memct_str++;
        memcpy(build->result, &(p->pkt[*next_idx]), rdlength);
        build->result[rdlength] = 0;
        *next_idx += rdlength;
        success = 1;
        break;
    case 15: { // MX
        uint16_t mx_preference = parse_u16(p->pkt, (*next_idx));
        *next_idx += 2;
        build->result = malloc(sizeof(char) * 262); // allow for "65536 "
        memct_str++;
        int pref_len = snprintf(build->result, 7, "%d ", mx_preference);
        if(parse_name(build->result + pref_len, p, dh->pkt_idx, next_idx)) {
            success = 1;
        } else {
            success = 0;
        }
        build->result[261] = 0;
        break; }
    case 16: // TXT
        // TODO: replace all \0 with \n ?? spec allows for
        //   "one or more <character-string>s"
        build->result = malloc(sizeof(char) * rdlength + 1);
        memct_str++;
        memcpy(build->result, &(p->pkt[*next_idx]), rdlength);
        build->result[rdlength] = 0;
        *next_idx += rdlength;
        success = 1;
        break;
    case 33: // SRV (MDNS stuff)
        *next_idx += 4; // skip priority, weight
        uint16_t srv_port = parse_u16(p->pkt, (*next_idx));
        *next_idx += 2;
        build->result = malloc(sizeof(char) * 262); // allow for "65536 "
        memct_str++;
        int port_len = snprintf(build->result, 7, "%d ", srv_port);
        if(parse_name(build->result + port_len, p, dh->pkt_idx, next_idx)) {
            success = 1;
        } else {
            success = 0;
        }
        build->result[261] = 0;
        break;
    case 47: // NSEC (DNS-SEC stuff)
        fprintf(stderr, "Unhandled: NSEC\n");
        *next_idx += rdlength;
        break;
    default:
        fprintf(stderr, "Unknown RR type %d\n", build->rrtype);
        *next_idx += rdlength;
        break;
    }

    if(success) {
        if(!*rtail) {
            *rtail = build;
        } else {
            (*rtail)->next = build;
        }
        return 1;
    } else {
        free_rsection(build);
        return 0;
    }
}

struct qsection* make_qsection() {
    struct qsection *q = malloc(sizeof(struct qsection));
    q->next = NULL;
    q->qname = malloc(sizeof(uint8_t) * 256);
    memct_str++;
    q->qname[0] = 0;
    q->qtype = 0xFFFF; // qtype and qclass invalid unless updated in parse
    q->qclass = 0xFFFF;

    DEBUG_MF("m_q q=%p qname=%p\n", (void*)q, q->qname);
    memct_qsec++;
    return q;
}

void free_qsection(struct qsection *q) {
    struct qsection *next;
#if DEBUG_MALLOC_FREE
    uint32_t counter = 0;
#endif
    while(q) {
        DEBUG_MF("f_q preFREE %d %p\n", counter++, (void*)q);
        next = q->next;
        if(q->qname) {
            DEBUG_MF("f_q FREE qname %p\n", q->qname);
            free(q->qname);
            memct_str--;
        }
        DEBUG_MF("f_q FREE %p\n", (void*)q);
        free(q);
        memct_qsec--;
        q = next;
    }
}

struct rsection* make_rsection() {
    struct rsection *r = malloc(sizeof(struct rsection));
    r->next = NULL;
    r->type = -1; // invalid
    r->rrtype = 0xFFFF; // invalid
    r->result = NULL;
    r->result_len = -1;

    DEBUG_MF("m_r r=%p result=%p\n", (void*)r, r->result);
    memct_rsec++;
    return r;
}

void free_rsection(struct rsection *r) {
    struct rsection *next;
#if DEBUG_MALLOC_FREE
    uint32_t counter = 0;
#endif
    while(r) {
        DEBUG_MF("f_r preFREE %d %p\n", counter++, (void*)r);
        next = r->next;
        if(r->result) {
            DEBUG_MF("f_r FREE result %p\n", r->result);
            free(r->result);
            memct_str--;
        }
        DEBUG_MF("f_r FREE %p\n", (void*)r);
        free(r);
        memct_rsec--;
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
    case 47: // NSEC
        return (const char*)&QT_NSEC;
    default:
        fprintf(stderr, "unknown query type %d\n", qtype);
        return (const char*)&QT_UNKNOWN;
    }
}

// RR types are a subset of Q types
const char* rrtype_str(uint16_t rrtype) {
    if(rrtype < 17) {
        return QT_NAMES[rrtype];
    }
    if(rrtype == 28) {
        return (const char*)&QT_AAAA;
    }
    if(rrtype == 33) {
        return (const char*)&QT_SRV;
    }
    fprintf(stderr, "unknown response type %d\n", rrtype);
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

void print_packet_info(struct ipheader *ih, struct udpheader *uh) {
    // for now assume IPV4
    struct in_addr src = {ih->src_ip};
    char src_ip[50];
    struct in_addr dst = {ih->dst_ip};
    char dst_ip[50];
    printf("%s:%d -> %s:%d\n", inet_ntop(AF_INET, &src, src_ip, 50),
            uh->src_port, 
            inet_ntop(AF_INET, &dst, dst_ip, 50),
            uh->dst_port);
}


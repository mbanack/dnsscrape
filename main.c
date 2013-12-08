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
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <assert.h>
#include <libconfig.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "debug.h"
#include "dns_types.h"

int quiet;
int show_section_counts;

void scrape_loop(pcap_t *capdev) {
    int cont = 1;
    const u_char *pkt;
    struct pcap_pkthdr hdr;
    struct packet p;
    struct ipheader ihead;
    struct udpheader uhead;
    struct dnsheader dhead;
    struct dnsheader *dh = &dhead;
    uint32_t internal_packet_no = 0;
    while(cont) {
        // should be using _dispatch() or _loop()
        

        fflush(stdout);
        fflush(stderr);
        p.len = 0;
        p.pkt = NULL;
        pkt = pcap_next(capdev, &hdr);
        if(!pkt) {
            if(!quiet) {
                printf("Got NULL packet.  Stop.\nRead %d packets (may have overflowed).\n", internal_packet_no);
            }
            break;
        }
        p.len = hdr.caplen;
        p.pkt = pkt;

        internal_packet_no++;

        if(is_udp(&p)) {
            if(p.len >= 55 && p.len <= 512) {
                parse_ipheader(&ihead, &p, 14);
                if(ihead.header_length < 5) {
                    // are our ip and udp headers the expected length?
                    fprintf(stderr, "Bad IP header length %d\n", ihead.header_length);
                    //continue;
                }
                parse_udpheader(&uhead, &p, 14 + (ihead.header_length << 2));
                parse_dnsheader(dh, &p, 14 + (ihead.header_length << 2) + 8);
                print_packet_info(&ihead, &uhead);
                if(!is_valid_dnsheader(dh)) {
                    //fprintf(stderr, "Failed parsing dns header\n");
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

                if(dh->qdcount > 8 || dh->ancount > 20 || dh->nscount > 8 || dh->arcount > 20) {
                    if(!quiet) {
                        fprintf(stderr, "Insane counts (%d %d %d %d)\n",
                                dh->qdcount, dh->ancount, dh->nscount, dh->arcount);
                    }
                    continue;
                }

                if(show_section_counts) {
                    DEBUG_MF("\n");
                    printf("  Starting parse #%d for counts (%d %d %d %d)\n",
                            internal_packet_no,
                            dh->qdcount, dh->ancount, dh->nscount, dh->arcount);
                }

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
                if(show_section_counts) {
                    printf("Successful parse #%d for counts (%d %d %d %d)\n",
                            internal_packet_no,
                            dh->qdcount, dh->ancount, dh->nscount, dh->arcount);
                }

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
const char DEFAULT_CONFIG[] = "/etc/dnsscrape.conf";
// default config file ~/.dnsscrape
// later move to /etc/dnsscrape.conf

#define OPT_SECTIONCOUNTS (0)
#define OPT_QUIET (1)
#define OPT_IFNAME (2)
#define OPT_FNAME (3)
#define OPT_CONFIGNAME (4)
#define OPT_ONLY53 (5)
#define NUM_OPTS (6)

int main(int argc, char *argv[]) {
    int opt;
    int ifnd = 0;
    int ffnd = 0;
    quiet = 0;
    show_section_counts = 0;
    char *ifname;
    const char *conf_ifname;
    char *fname;
    char *configname;
    int only53 = 0;
    
    // has this option been set on the command line?
    //   if so, override any conf value
    int cmdline_set[NUM_OPTS];
    for(int i = 0; i < NUM_OPTS; i++) {
        cmdline_set[i] = 0;
    }

    int option_index = 0;
    struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"counts",  no_argument,       0, 'n'},
        {"53",      no_argument,       &only53, 1},
        {0, 0, 0, 0}
    };
    while((opt = getopt_long(argc, argv, "nqi:f:c:",
                    long_options, &option_index)) != -1) {
        switch (opt) {
        case 'n':
            cmdline_set[OPT_SECTIONCOUNTS] = 1;
            show_section_counts = 1;
            break;
        case 'q':
            cmdline_set[OPT_QUIET] = 1;
            quiet = 1;
            break;
        case 'i':
            cmdline_set[OPT_IFNAME] = 1;
            ifname = optarg;
            ifnd = 1;
            break;
        case 'f':
            cmdline_set[OPT_FNAME] = 1;
            fname = optarg;
            ffnd = 1;
            break;
        case 'c':
            cmdline_set[OPT_CONFIGNAME] = 1;
            configname = optarg;
            break;
        case 0: // getopt_long set a variable, just keep going
            break;
        default:
            fprintf(stderr,
"Usage: %s [--53] [-p] [-q] [-i iface | -f file.pcap] [-c | --config filename]\n\
-i: use specified interface for capture.\n\
-f: run using saved pcap file.  If -f is given, -i is ignored.\n\
-n: show section counts (also --counts)\n\
-q: quiet\n\
-c filename, --config filename: specify config file\n\
--53: only parse packets on port 53\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(only53) {
        cmdline_set[OPT_ONLY53] = 1;
    }


    if(cmdline_set[OPT_CONFIGNAME]) {
        // set above
    } else {
        configname = (char*)&DEFAULT_CONFIG[0];
    }

    printf("configname is %s\n", configname);
    // try to load config file
    //   but command line options should override config file
    int conf_test = access(configname, R_OK);
    if(conf_test == 0) {
        config_t cfg;
        config_init(&cfg);

        if(!config_read_file(&cfg, configname)) {
            printf("config read failed: %s at %d\n", config_error_text(&cfg), config_error_line(&cfg));
            config_destroy(&cfg);
        } else {
            if(!cmdline_set[OPT_SECTIONCOUNTS]) {
                config_lookup_bool(&cfg, "sectioncounts", &show_section_counts);
            }
            if(!cmdline_set[OPT_QUIET]) {
                config_lookup_bool(&cfg, "quiet", &quiet);
            }
            if(!cmdline_set[OPT_IFNAME]) {
                if(config_lookup_string(&cfg, "ifname", &conf_ifname)) {
                    strncpy(ifname, conf_ifname, strlen(conf_ifname));
                    ifnd = 1;
                }
            }
            if(!cmdline_set[OPT_ONLY53]) {
                config_lookup_bool(&cfg, "only53", &only53);
            }
        }
        config_destroy(&cfg);
    } else {
        printf("Couldn't find conf file %s\n", configname);
    }


    if(quiet) {
        show_section_counts = 0;
    }

    char ebuf[PCAP_ERRBUF_SIZE];
    if(ffnd) {
        if(!quiet) {
            printf("Using saved PCAP file %s\n", fname);
        }

        pcap_t *capdev = pcap_open_offline(fname, ebuf);
        if(!capdev) {
            fprintf(stderr, "Could not open capture file.  %s\n", ebuf);
            return -1;
        }
        pcap_set_buffer_size(capdev, 1024);

        //pcap_setfilter(capdev, ?????); // have option to set just port 53 :)
        // but it is *really nice* to be able to sniff dns on non-53 ports
        scrape_loop(capdev);

        pcap_close(capdev);
    } else {
        if(!ifnd) {
            printf("Using default device \"any\"... override with \"-i ifname\"\n");
            // pcap_create will use "any" if given "", so default to that
            ifname = (char*)&DEFAULT_IFNAME[0];
        }

        if(!quiet) {
            printf("Using interface %s\n", ifname);
        }

        pcap_t *capdev = pcap_create(ifname, ebuf);
        if(!capdev) {
            fprintf(stderr, "pcap_create failed.  %s\n", ebuf);
        }
        // set options on capdev ?
        //    snaplen, promisc/monitor, timeout, buffer_size, timestamp type
        //pcap_setfilter(capdev, ?????); // have option to set just port 53 :)
        // but it is *really nice* to be able to sniff dns on non-53 ports

        int act_ret = pcap_activate(capdev);
        if(!!act_ret) {
            fprintf(stderr, "\nCould not activate capture device (code %d).  Sorry!\n", act_ret);
            fprintf(stderr, "  pcap says: %s\n", pcap_geterr(capdev));
            return act_ret;
        }

        if(only53) {
            fprintf(stderr, "Trying to filter to port 53 only\n");
            struct bpf_program fp;
            if(!!pcap_compile(capdev, &fp, "port 53", 1, PCAP_NETMASK_UNKNOWN)) {
                fprintf(stderr, "Couldn't compile filter\n");
                if(!!pcap_setfilter(capdev, &fp)) {
                    fprintf(stderr, "Couldn't set filter\n");
                }
            }
        }

        pcap_set_promisc(capdev, 1);
        pcap_set_buffer_size(capdev, 1024);

        scrape_loop(capdev);

        pcap_close(capdev);
    }
    return 0;
}


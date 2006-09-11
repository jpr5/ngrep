/*
 * $Id$
 *
 * Copyright (c) 2005  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#if defined(BSD) || defined(SOLARIS) || defined(MACOSX)
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <sys/tty.h>
#include <pwd.h>
#endif

#if defined(OSF1)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <sys/mbuf.h>
#include <arpa/inet.h>
#include <unistd>
#include <pwd.h>
#endif

#if defined(LINUX)
#include <getopt.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#endif

#if defined(AIX)
#include <sys/machine.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <getopt.h>
#include <winsock2.h>
#include <types.h>
#include <inet_ntop.h>

#define strcasecmp stricmp

#else

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#endif

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#if !defined(_WIN32)
#include <errno.h>
#include <sys/ioctl.h>
#endif

#include <pcap.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if USE_IPv6 && !defined(_WIN32)
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#if USE_PCRE
#include "pcre-5.0/pcre.h"
#else
#include "regex-0.12/regex.h"
#endif

#include "ngrep.h"


static char rcsver[] = "$Revision$";

/*
 * Configuration Options
 */

uint16_t snaplen = 65535, limitlen = 65535, promisc = 1, to = 100;
uint16_t match_after = 0, keep_matching = 0, matches = 0, max_matches = 0;

uint8_t  re_match_word = 0, re_ignore_case = 0, re_multiline_match = 1;
uint8_t  show_empty = 0, show_hex = 0, show_proto = 0, quiet = 0;
uint8_t  invert_match = 0, bin_match = 0;
uint8_t  live_read = 1, want_delay = 0;
uint8_t  dont_dropprivs = 0;

char *read_file = NULL, *dump_file = NULL;
char *usedev = NULL;

char nonprint_char = '.';

/*
 * GNU Regex/PCRE
 */

#if USE_PCRE
int32_t err_offset;
char *re_err = NULL;

pcre *pattern = NULL;
pcre_extra *pattern_extra = NULL;
#else
const char *re_err = NULL;

struct re_pattern_buffer pattern;
#endif

/*
 * Matching
 */

char *match_data = NULL, *bin_data = NULL;
uint16_t match_len = 0;
int8_t (*match_func)() = &blank_match_func;

int8_t dump_single = 0;
void (*dump_func)(unsigned char *, uint32_t) = &dump_formatted;

/*
 * BPF/Network
 */

char *filter = NULL, *filter_file = NULL;
char pc_err[PCAP_ERRBUF_SIZE];
uint8_t link_offset;

pcap_t *pd = NULL;
pcap_dumper_t *pd_dump = NULL;
struct bpf_program pcapfilter;
struct in_addr net, mask;

/*
 * Timestamp/delay functionality
 */

struct timeval prev_ts = {0, 0}, prev_delay_ts = {0,0};
#if defined(_WIN32)
struct timeval delay_tv;
FD_SET delay_fds;
SOCKET delay_socket = 0;
#endif

void (*print_time)() = NULL, (*dump_delay)() = dump_delay_proc_init;


/*
 * When !Win32, windowsize stuff
 */

uint32_t ws_row, ws_col = 80, ws_col_forced = 0;


int main(int argc, char **argv) {
    int32_t c;

    signal(SIGINT,   clean_exit);
    signal(SIGABRT,  clean_exit);

#if !defined(_WIN32)
    signal(SIGQUIT,  clean_exit);
    signal(SIGPIPE,  clean_exit);
    signal(SIGWINCH, update_windowsize);
#endif

    while ((c = getopt(argc, argv, "LNhXViwqpevxlDtTRMs:n:c:d:A:I:O:S:P:F:W:")) != EOF) {
        switch (c) {
            case 'W': {
                if (!strcasecmp(optarg, "normal"))
                    dump_func = &dump_formatted;
                else if (!strcasecmp(optarg, "byline"))
                    dump_func = &dump_byline;
                else if (!strcasecmp(optarg, "none"))
                    dump_func = &dump_unwrapped;
                else if (!strcasecmp(optarg, "single")) {
                    dump_func = &dump_unwrapped;
                    dump_single = 1;
                } else {
                    printf("fatal: unknown wrap method '%s'\n", optarg);
                    usage(-1);
                }
            } break;

            case 'F':
                filter_file = optarg;
                break;
            case 'P':
                nonprint_char = *optarg;
                break;
            case 'S':
                limitlen = atoi(optarg);
                break;
            case 'O':
                dump_file = optarg;
                break;
            case 'I':
                read_file = optarg;
                break;
            case 'A':
                match_after = atoi(optarg) + 1;
                break;
#if defined(_WIN32)
            case 'L':
                win32_listdevices();
                clean_exit(0);
            case 'd':
                usedev = win32_usedevice(optarg);
                break;
#else
            case 'L':
                perror("-L is a Win32-only option");
                clean_exit(-1);
            case 'd':
                usedev = optarg;
                break;
#endif
            case 'c':
                ws_col_forced = atoi(optarg);
                break;
            case 'n':
                max_matches = atoi(optarg);
                break;
            case 's': {
                uint16_t value = atoi(optarg);
                if (value > 0)
                    snaplen = value;
            } break;
            case 'M':
                re_multiline_match = 0;
                break;
            case 'R':
                dont_dropprivs = 1;
                break;
            case 'T':
                print_time = &print_time_diff;
#if defined(_WIN32)
                prev_ts.tv_sec  = (uint32_t)time(NULL);
                prev_ts.tv_usec = 0;
#else
                gettimeofday(&prev_ts, NULL);
#endif
                break;
            case 't':
                print_time = &print_time_absolute;
                break;
            case 'D':
                want_delay = 1;
                break;
            case 'l':
                setvbuf(stdout, NULL, _IOLBF, 0);
                break;
            case 'x':
                show_hex++;
                break;
            case 'v':
                invert_match++;
                break;
            case 'e':
                show_empty++;
                break;
            case 'p':
                promisc = 0;
                break;
            case 'q':
                quiet++;
                break;
            case 'w':
                re_match_word++;
                break;
            case 'i':
                re_ignore_case++;
                break;
            case 'V':
                version();
            case 'X':
                bin_match++;
                break;
            case 'N':
                show_proto++;
                break;
            case 'h':
                usage(0);
            default:
                usage(-1);
        }
    }

    if (show_hex && dump_func != &dump_formatted) {
        printf("fatal: -x (hex dump) is incompatible with -W (alternate format)\n");
        usage(-1);
    }

    if (argv[optind])
        match_data = argv[optind++];

    if (read_file) {

        if (!(pd = pcap_open_offline(read_file, pc_err))) {
            perror(pc_err);
            clean_exit(-1);
        }

        live_read = 0;
        printf("input: %s\n", read_file);

    } else {

        char *dev = usedev ? usedev : pcap_lookupdev(pc_err);

        if (!dev) {
            perror(pc_err);
            clean_exit(-1);
        }

        if ((pd = pcap_open_live(dev, snaplen, promisc, to, pc_err)) == NULL) {
            perror(pc_err);
            clean_exit(-1);
        }

        if (pcap_lookupnet(dev, &net.s_addr, &mask.s_addr, pc_err) == -1) {
            perror(pc_err);
            memset(&net, 0, sizeof(net));
            memset(&mask, 0, sizeof(mask));
        }

        if (quiet < 2) {
            printf("interface: %s", dev);
            if (net.s_addr && mask.s_addr) {
                printf(" (%s/", inet_ntoa(net));
                printf("%s)", inet_ntoa(mask));
            }
            printf("\n");
        }
    }

#if !defined(_WIN32)
    drop_privs();
#endif

    if (filter_file) {
        char buf[1024] = {0};
        FILE *f = fopen(filter_file, "r");

        if (!f || !fgets(buf, sizeof(buf)-1, f)) {
            fprintf(stderr, "fatal: unable to get filter from %s: %s\n", filter_file, strerror(errno));
            usage(-1);
        }

        fclose(f);

        filter = get_filter_from_string(buf);

        if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr)) {
            pcap_perror(pd, "pcap compile");
            clean_exit(-1);
        }

    } else if (argv[optind]) {
        filter = get_filter_from_argv(&argv[optind]);

        if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr)) {
            free(filter);
            filter = get_filter_from_argv(&argv[optind-1]);

#if USE_PCAP_RESTART
            PCAP_RESTART_FUNC();
#endif
            if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr)) {
                pcap_perror(pd, "pcap compile");
                clean_exit(-1);
            } else match_data = NULL;
        }

    } else {
        char *default_filter = BPF_FILTER_IP;

        if (pcap_compile(pd, &pcapfilter, default_filter, 0, mask.s_addr)) {
            pcap_perror(pd, "pcap compile");
            clean_exit(-1);
        }
    }

    if (filter && quiet < 2)
        printf("filter: %s\n", filter);

    if (pcap_setfilter(pd, &pcapfilter)) {
        pcap_perror(pd, "pcap set");
        clean_exit(-1);
    }

    if (match_data) {
        if (bin_match) {
            uint32_t i = 0, n;
            uint32_t len;
            char *s, *d;

            if (re_match_word || re_ignore_case) {
                fprintf(stderr, "fatal: regex switches are incompatible with binary matching\n");
                clean_exit(-1);
            }

            len = (uint32_t)strlen(match_data);
            if (len % 2 != 0 || !strishex(match_data)) {
                fprintf(stderr, "fatal: invalid hex string specified\n");
                clean_exit(-1);
            }

            bin_data = malloc(len / 2);
            memset(bin_data, 0, len / 2);
            d = bin_data;

            if ((s = strchr(match_data, 'x')))
                len -= (uint32_t)(++s - match_data - 1);
            else s = match_data;

            while (i <= len) {
                sscanf(s+i, "%2x", &n);
                *d++ = n;
                i += 2;
            }

            match_len = len / 2;
            match_func = &bin_match_func;

        } else {

#if USE_PCRE
            uint32_t pcre_options = PCRE_UNGREEDY;

            if (re_ignore_case)
                pcre_options |= PCRE_CASELESS;

            if (re_multiline_match)
                pcre_options |= PCRE_DOTALL;
#else
            re_syntax_options = RE_CHAR_CLASSES | RE_NO_BK_PARENS | RE_NO_BK_VBAR |
                                RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS;

            if (re_multiline_match)
                re_syntax_options |= RE_DOT_NEWLINE;

            if (re_ignore_case) {
                uint32_t i;
                char *s;

                pattern.translate = (char*)malloc(256);
                s = pattern.translate;

                for (i = 0; i < 256; i++)
                    s[i] = i;
                for (i = 'A'; i <= 'Z'; i++)
                    s[i] = i + 32;

                s = match_data;
                while (*s)
                    *s++ = tolower(*s);

            } else pattern.translate = NULL;
#endif

            if (re_match_word) {
                char *word_regex = malloc(strlen(match_data) * 3 + strlen(WORD_REGEX));
                sprintf(word_regex, WORD_REGEX, match_data, match_data, match_data);
                match_data = word_regex;
            }

#if USE_PCRE
            pattern = pcre_compile(match_data, pcre_options, (const char **)&re_err, &err_offset, 0);

            if (!pattern) {
                fprintf(stderr, "compile failed: %s\n", re_err);
                clean_exit(-1);
            }

            pattern_extra = pcre_study(pattern, 0, (const char **)&re_err);
#else
            re_err = re_compile_pattern(match_data, strlen(match_data), &pattern);
            if (re_err) {
                fprintf(stderr, "regex compile: %s\n", re_err);
                clean_exit(-1);
            }

            pattern.fastmap = (char*)malloc(256);
            if (re_compile_fastmap(&pattern)) {
                perror("fastmap compile failed");
                clean_exit(-1);
            }
#endif

            match_func = &re_match_func;
        }

        if (quiet < 2 && match_data && strlen(match_data))
            printf("%smatch: %s%s\n", invert_match?"don't ":"",
                   (bin_data && !strchr(match_data, 'x'))?"0x":"", match_data);
    }

    if (filter) free(filter);
    if (re_match_word) free(match_data);

    switch(pcap_datalink(pd)) {
        case DLT_EN10MB:
            link_offset = ETHHDR_SIZE;
            break;

        case DLT_IEEE802:
            link_offset = TOKENRING_SIZE;
            break;

        case DLT_FDDI:
            link_offset = FDDIHDR_SIZE;
            break;

        case DLT_SLIP:
            link_offset = SLIPHDR_SIZE;
            break;

        case DLT_PPP:
            link_offset = PPPHDR_SIZE;
            break;

#if HAVE_DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:
            link_offset = LOOPHDR_SIZE;
            break;

#if HAVE_DLT_RAW
        case DLT_RAW:
            link_offset = RAWHDR_SIZE;
            break;
#endif

#if HAVE_DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            link_offset = ISDNHDR_SIZE;
            break;
#endif

#if HAVE_DLT_IEEE802_11
        case DLT_IEEE802_11:
            link_offset = IEEE80211HDR_SIZE;
            break;
#endif

        default:
            fprintf(stderr, "fatal: unsupported interface type %u\n", pcap_datalink(pd));
            clean_exit(-1);
    }

    if (dump_file) {
        if (!(pd_dump = pcap_dump_open(pd, dump_file))) {
            fprintf(stderr, "fatal: %s\n", pcap_geterr(pd));
            clean_exit(-1);
        } else printf("output: %s\n", dump_file);
    }

#if !defined(_WIN32)
    update_windowsize(0);
#endif

#if defined(_WIN32)
    win32_initwinsock();
#endif

    while (pcap_loop(pd, 0, (pcap_handler)process, 0));

    clean_exit(0);

    /* NOT REACHED */
    return 0;
}

void process(u_char *d, struct pcap_pkthdr *h, u_char *p) {
    struct ip      *ip_packet  = (struct ip *)    (p + link_offset);
#if USE_IPv6
    struct ip6_hdr *ip6_packet = (struct ip6_hdr*)(p + link_offset);
#endif

    uint32_t ip_ver   = ip_packet->ip_v;

    uint8_t  ip_proto = 0;
    uint32_t ip_hl    = 0;
    uint32_t ip_off   = 0;

    uint8_t  fragmented  = 0;
    uint16_t frag_offset = 0;
    uint32_t frag_id     = 0;

    char ip_src[INET6_ADDRSTRLEN + 1],
         ip_dst[INET6_ADDRSTRLEN + 1];

    unsigned char *data;
    uint32_t len = 0;

    switch (ip_ver) {

        case 4: {

#if defined(AIX)
#undef ip_hl
            ip_hl       = ip_packet->ip_ff.ip_fhl * 4;
#else
            ip_hl       = ip_packet->ip_hl * 4;
#endif
            ip_proto    = ip_packet->ip_p;
            ip_off      = ntohs(ip_packet->ip_off);

            fragmented  = ip_off & (IP_MF | IP_OFFMASK);
            frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
            frag_id     = ntohs(ip_packet->ip_id);

            inet_ntop(AF_INET, (const void *)&ip_packet->ip_src, ip_src, sizeof(ip_src));
            inet_ntop(AF_INET, (const void *)&ip_packet->ip_dst, ip_dst, sizeof(ip_dst));
        } break;

#if USE_IPv6
        case 6: {

            ip_hl    = sizeof(struct ip6_hdr);
            ip_proto = ip6_packet->ip6_nxt;

            if (ip_proto == IPPROTO_FRAGMENT) {
                struct ip6_frag *ip6_fraghdr;

                ip6_fraghdr = (struct ip6_frag *)(((unsigned char *)ip6_packet) + ip_hl);
                ip_hl      += sizeof(struct ip6_frag);
                ip_proto    = ip6_fraghdr->ip6f_nxt;

                fragmented  = 1;
                frag_offset = ntohs(ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
                frag_id     = ntohl(ip6_fraghdr->ip6f_ident);
            }

            inet_ntop(AF_INET6, (const void *)&ip6_packet->ip6_src, ip_src, sizeof(ip_src));
            inet_ntop(AF_INET6, (const void *)&ip6_packet->ip6_dst, ip_dst, sizeof(ip_dst));
        } break;
#endif
    }

    if (quiet < 1) {
        printf("#");
        fflush(stdout);
    }

    switch (ip_proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp     = (struct tcphdr *)(((unsigned char *)ip_packet) + ip_hl);
            uint16_t tcphdr_offset = (frag_offset) ? 0 : (tcp->th_off * 4);

            data = ((unsigned char *)tcp) + tcphdr_offset;

            switch (ip_ver) {
                case 4: {
                    if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                        len -= ip_hl + tcphdr_offset;
                    else
                        len = h->caplen - link_offset - ip_hl - tcphdr_offset;
                } break;

#if USE_IPv6
                case 6: {
                    if ((len = ntohs(ip6_packet->ip6_plen + ip_hl)) < h->caplen)
                        len -= ip_hl + tcphdr_offset;
                    else
                        len = h->caplen - link_offset - ip_hl - tcphdr_offset;
                } break;
#endif
            }

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), tcp->th_flags,
                        tcphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        case IPPROTO_UDP: {
            struct udphdr *udp     = (struct udphdr *)(((unsigned char *)ip_packet) + ip_hl);
            uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(struct udphdr);

            data = ((unsigned char *)udp) + udphdr_offset;

            switch (ip_ver) {
                case 4: {
                    if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                        len -= ip_hl + udphdr_offset;
                    else
                        len = h->caplen - link_offset - ip_hl - udphdr_offset;
                } break;

#if USE_IPv6
                case 6: {
                    if ((len = ntohs(ip6_packet->ip6_plen + ip_hl)) < h->caplen)
                        len -= ip_hl + udphdr_offset;
                    else
                        len = h->caplen - link_offset - ip_hl - udphdr_offset;
                } break;
#endif
            }

            dump_packet(h, p, ip_proto, data, len, ip_src, ip_dst,
#if HAVE_DUMB_UDPHDR
                        ntohs(udp->source), ntohs(udp->dest), 0,
#else
                        ntohs(udp->uh_sport), ntohs(udp->uh_dport), 0,
#endif
                        udphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        case IPPROTO_ICMP: {
            struct icmp *ic4        = (struct icmp *)(((unsigned char *)ip_packet) + ip_hl);
            uint16_t icmphdr_offset = (frag_offset) ? 0 : 4;

            data = ((unsigned char *)ic4) + icmphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + icmphdr_offset;
            else
                len = h->caplen - link_offset - ip_hl - icmphdr_offset;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, ic4->icmp_type, ic4->icmp_code, 0,
                        icmphdr_offset, fragmented, frag_offset, frag_id);
        } break;

#if USE_IPv6
        case IPPROTO_ICMPV6: {
            struct icmp6_hdr *ic6   = (struct icmp6_hdr *)(((unsigned char *)ip6_packet) + ip_hl);
            uint16_t icmphdr_offset = (frag_offset) ? 0 : 4;

            data = ((unsigned char *)ic6) + icmphdr_offset;

            if ((len = ntohs(ip6_packet->ip6_plen + ip_hl)) < h->caplen)
                len -= ip_hl + icmphdr_offset;
            else
                len = h->caplen - link_offset - ip_hl - icmphdr_offset;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, ic6->icmp6_type, ic6->icmp6_code, 0,
                        icmphdr_offset, fragmented, frag_offset, frag_id);
        } break;
#endif

        case IPPROTO_IGMP: {
            struct igmp *ig         = (struct igmp *)(((unsigned char *)ip_packet) + ip_hl);
            uint16_t igmphdr_offset = (frag_offset) ? 0 : 4;

            data = ((unsigned char *)ig) + igmphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + igmphdr_offset;
            else
                len = h->caplen - link_offset - ip_hl - igmphdr_offset;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, ig->igmp_type, ig->igmp_code, 0,
                        igmphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        default: {
            data = (((unsigned char *)ip_packet) + ip_hl);

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl;
            else
                len = h->caplen - link_offset - ip_hl;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, 0, 0, 0,
                        0, fragmented, frag_offset, frag_id);
        } break;

    }

    if (max_matches && matches >= max_matches)
        clean_exit(0);

    if (match_after && keep_matching)
        keep_matching--;
}

void dump_packet(struct pcap_pkthdr *h, u_char *p, uint8_t proto, unsigned char *data, uint32_t len,
                 const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint8_t flags,
                 uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id) {

    if (!show_empty && len == 0)
        return;

    if (len > limitlen)
        len = limitlen;

    if ((len > 0 && match_func(data, len) == invert_match) && !keep_matching)
        return;

    if (!live_read && want_delay)
        dump_delay(h);

    {
        char ident;

        switch (proto) {
            case IPPROTO_TCP:    ident = TCP;     break;
            case IPPROTO_UDP:    ident = UDP;     break;
            case IPPROTO_ICMP:   ident = ICMP;    break;
            case IPPROTO_ICMPV6: ident = ICMPv6;  break;
            case IPPROTO_IGMP:   ident = IGMP;    break;
            default:             ident = UNKNOWN; break;
        }

        printf("\n%c", ident);
    }

    if (show_proto)
        printf("(%u)", proto);

    printf(" ");

    if (print_time)
        print_time(h);

    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && (sport || dport) && (hdr_offset || frag_offset == 0))

        printf("%s:%u -> %s:%u", ip_src, sport, ip_dst, dport);

    else

        printf("%s -> %s", ip_src, ip_dst);

    if (proto == IPPROTO_TCP && flags)
        printf(" [%s%s%s%s%s%s%s%s]",
               (flags & TH_ACK) ? "A" : "",
               (flags & TH_SYN) ? "S" : "",
               (flags & TH_RST) ? "R" : "",
               (flags & TH_FIN) ? "F" : "",
               (flags & TH_URG) ? "U" : "",
               (flags & TH_PUSH)? "P" : "",
               (flags & TH_ECE) ? "E" : "",
               (flags & TH_CWR) ? "C" : "");

    switch (proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
        case IPPROTO_IGMP:
            printf(" %u:%u", sport, dport);
    }

    if (frag)
        printf(" %s%u@%u:%u",
               frag_offset?"+":"", frag_id, frag_offset, len);

    if (dump_single)
        printf(" ");
    else
        printf("\n");

    if (quiet < 3)
        dump_func(data, len);

    if (pd_dump)
        pcap_dump((u_char*)pd_dump, h, p);
}

int8_t re_match_func(unsigned char *data, uint32_t len) {
#if USE_PCRE
    switch(pcre_exec(pattern, 0, data, (int32_t)len, 0, 0, 0, 0)) {
        case PCRE_ERROR_NULL:
        case PCRE_ERROR_BADOPTION:
        case PCRE_ERROR_BADMAGIC:
        case PCRE_ERROR_UNKNOWN_NODE:
        case PCRE_ERROR_NOMEMORY:
            perror("she's dead, jim\n");
            clean_exit(-2);

        case PCRE_ERROR_NOMATCH:
            return 0;
    }
#else
    switch (re_search(&pattern, data, (int32_t)len, 0, len, 0)) {
        case -2:
            perror("she's dead, jim\n");
            clean_exit(-2);

        case -1:
            return 0;
    }
#endif

    if (max_matches)
        matches++;

    if (match_after && keep_matching != match_after)
        keep_matching = match_after;

    return 1;
}

int8_t bin_match_func(unsigned char *data, uint32_t len) {
    int32_t stop = len - match_len;
    int32_t i    = 0;

    if (stop < 0)
        return 0;

    while (i <= stop)
        if (!memcmp(data+(i++), bin_data, match_len)) {
            if (max_matches)
                matches++;

            if (match_after && keep_matching != match_after)
                keep_matching = match_after;

            return 1;
        }

    return 0;
}


int8_t blank_match_func(unsigned char *data, uint32_t len) {
    if (max_matches)
        matches++;

    return 1;
}

void dump_byline(unsigned char *data, uint32_t len) {
    if (len > 0) {
        const unsigned char *s = data;

        while (s < data + len) {
            printf("%c", (*s == '\n' || isprint(*s)) ? *s : nonprint_char);
            s++;
        }

        printf("\n");
    }
}

void dump_unwrapped(unsigned char *data, uint32_t len) {
    if (len > 0) {
        const unsigned char *s = data;

        while (s < data + len) {
            printf("%c", isprint(*s) ? *s : nonprint_char);
            s++;
        }

        printf("\n");
    }
}

void dump_formatted(unsigned char *data, uint32_t len) {
    if (len > 0) {
        unsigned char *str = data;
             uint8_t width = show_hex ? 16 : (ws_col-5);
                uint32_t i = 0,
                         j = 0;

        while (i < len) {
            printf("  ");

            if (show_hex)
                for (j = 0; j < width; j++) {
                    if (i + j < len)
                        printf("%02x ", str[j]);
                    else printf("   ");

                    if ((j+1) % (width/2) == 0)
                        printf("   ");
                }

            for (j = 0; j < width; j++)
                if (i + j < len)
                    printf("%c", isprint(str[j]) ? str[j] : nonprint_char);
                else printf(" ");

            str += width;
            i   += j;

            printf("\n");
        }
    }
}

char *get_filter_from_string(char *str) {
    char *mine, *s;
    uint32_t len;

    if (!str || !*str)
        return NULL;

    len = (uint32_t)strlen(str);

    for (s = str; *s; s++)
        if (*s == '\r' || *s == '\n')
            *s = ' ';

    if (!(mine = (char*)malloc(len + sizeof(BPF_MAIN_FILTER))))
        return NULL;

    memset(mine, 0, len + sizeof(BPF_MAIN_FILTER));

    sprintf(mine, BPF_MAIN_FILTER, str);

    return mine;
}

char *get_filter_from_argv(char **argv) {
    char **arg = argv, *theirs, *mine;
    char *from, *to;
    uint32_t len = 0;

    if (!*arg)
        return NULL;

    while (*arg)
        len += (uint32_t)strlen(*arg++) + 1;

    if (!(theirs = (char*)malloc(len + 1)) ||
        !(mine = (char*)malloc(len + sizeof(BPF_MAIN_FILTER))))
        return NULL;

    memset(theirs, 0, len + 1);
    memset(mine, 0, len + sizeof(BPF_MAIN_FILTER));

    arg = argv;
    to = theirs;

    while ((from = *arg++)) {
        while ((*to++ = *from++));
        *(to-1) = ' ';
    }

    sprintf(mine, BPF_MAIN_FILTER, theirs);

    free(theirs);
    return mine;
}


uint8_t strishex(char *str) {
    char *s;

    if ((s = strchr(str, 'x')))
        s++;
    else
        s = str;

    while (*s)
        if (!isxdigit(*s++))
            return 0;

    return 1;
}


void print_time_absolute(struct pcap_pkthdr *h) {
    struct tm *t = localtime((const time_t *)&h->ts.tv_sec);

    printf("%02u/%02u/%02u %02u:%02u:%02u.%06u ",
           t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour,
           t->tm_min, t->tm_sec, (uint32_t)h->ts.tv_usec);
}

void print_time_diff(struct pcap_pkthdr *h) {
    uint32_t secs, usecs;

    secs = h->ts.tv_sec - prev_ts.tv_sec;
    if (h->ts.tv_usec >= prev_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_ts.tv_usec - h->ts.tv_usec);
    }

    printf("+%u.%06u ", secs, usecs);

    prev_ts.tv_sec  = h->ts.tv_sec;
    prev_ts.tv_usec = h->ts.tv_usec;
}

void dump_delay_proc_init(struct pcap_pkthdr *h) {
    dump_delay = &dump_delay_proc;

    prev_delay_ts.tv_sec  = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;

    dump_delay(h);
}

void dump_delay_proc(struct pcap_pkthdr *h) {
    uint32_t secs, usecs;

    secs = h->ts.tv_sec - prev_delay_ts.tv_sec;
    if (h->ts.tv_usec >= prev_delay_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_delay_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_delay_ts.tv_usec - h->ts.tv_usec);
    }

#ifdef _WIN32
    {
        // grevious hack, yes, but windows sucks.  sorry. :(   --jordan
        if ((delay_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            perror("delay socket creation failed, disabling -D");
            Sleep(3000); // give them time to read the message
            want_delay = 0;
            return;
        }

        FD_ZERO(&delay_fds);
        FD_SET(delay_socket, &delay_fds);

        delay_tv.tv_sec  = secs;
        delay_tv.tv_usec = usecs;

        if (select(0, &delay_fds, 0, 0, &delay_tv) == -1)
            fprintf(stderr, "WSAGetLastError = %u\n", WSAGetLastError());

        closesocket(delay_socket);
        delay_socket = 0; // in case someone ^C's out of me
    }
#else
    sleep(secs);
    usleep(usecs);
#endif

    prev_delay_ts.tv_sec  = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;
}

#if !defined(_WIN32)
void update_windowsize(int32_t e) {
    if (e == 0 && ws_col_forced)

        ws_col = ws_col_forced;

    else if (!ws_col_forced) {
        const struct winsize ws;

        if (!ioctl(0, TIOCGWINSZ, &ws)) {
            ws_row = ws.ws_row;
            ws_col = ws.ws_col;
        } else {
            ws_row = 24;
            ws_col = 80;
        }
    }
}

void drop_privs(void) {
    struct passwd *pw;
    uid_t newuid;
    gid_t newgid;

    if ((getuid() || geteuid()) || dont_dropprivs || !USE_DROPPRIVS)
        return;

    pw = getpwnam(DROPPRIVS_USER);
    if (!pw) {
        perror("attempt to drop privileges failed: getpwnam failed");
        clean_exit(-1);
    }

    newgid = pw->pw_gid;
    newuid = pw->pw_uid;

    if (getgroups(0, NULL) > 0)
        if (setgroups(1, &newgid) == -1) {
            perror("attempt to drop privileges failed");
            clean_exit(-1);
        }

    if (((getgid()  != newgid) && (setgid(newgid)  == -1)) ||
        ((getegid() != newgid) && (setegid(newgid) == -1)) ||
        ((getuid()  != newuid) && (setuid(newuid)  == -1)) ||
        ((geteuid() != newuid) && (seteuid(newuid) == -1))) {

        perror("attempt to drop privileges failed");
        clean_exit(-1);
    }
}
#endif

void usage(int8_t e) {
    printf("usage: ngrep <-"
#if defined(_WIN32)
           "L"
#endif
           "hNXViwqpevxlDtTRM> <-IO pcap_dump> <-n num> <-d dev> <-A num>\n"
           "             <-s snaplen> <-S limitlen> <-W normal|byline|single|none> <-c cols>\n"
           "             <-P char> <-F file> <match expression> <bpf filter>\n"
           "   -h  is help/usage\n"
           "   -V  is version information\n"
           "   -q  is be quiet (don't print packet reception hash marks)\n"
           "   -e  is show empty packets\n"
           "   -i  is ignore case\n"
           "   -v  is invert match\n"
           "   -R  is don't do privilege revocation logic\n"
           "   -x  is print in alternate hexdump format\n"
           "   -X  is interpret match expression as hexadecimal\n"
           "   -w  is word-regex (expression must match as a word)\n"
           "   -p  is don't go into promiscuous mode\n"
           "   -l  is make stdout line buffered\n"
           "   -D  is replay pcap_dumps with their recorded time intervals\n"
           "   -t  is print timestamp every time a packet is matched\n"
           "   -T  is print delta timestamp every time a packet is matched\n"
           "   -M  is don't do multi-line match (do single-line match instead)\n"
           "   -I  is read packet stream from pcap format file pcap_dump\n"
           "   -O  is dump matched packets in pcap format to pcap_dump\n"
           "   -n  is look at only num packets\n"
           "   -A  is dump num packets after a match\n"
           "   -s  is set the bpf caplen\n"
           "   -S  is set the limitlen on matched packets\n"
           "   -W  is set the dump format (normal, byline, single, none)\n"
           "   -c  is force the column width to the specified size\n"
           "   -P  is set the non-printable display char to what is specified\n"
           "   -F  is read the bpf filter from the specified file\n"
           "   -N  is show sub protocol number\n"
#if defined(_WIN32)
           "   -d  is use specified device (index) instead of the pcap default\n"
           "   -L  is show the winpcap device list index\n"
#else
           "   -d  is use specified device instead of the pcap default\n"
#endif
           "");

    exit(e);
}


void version(void) {
    printf("ngrep: V%s, %s\n", VERSION, rcsver);
    exit(0);
}


void clean_exit(int32_t sig) {
    struct pcap_stat s;

    if (quiet < 1 && sig >= 0)
        printf("exit\n");

#if USE_PCRE
    if (pattern)       pcre_free(pattern);
    if (pattern_extra) pcre_free(pattern_extra);
#else
    if (pattern.translate) free(pattern.translate);
    if (pattern.fastmap)   free(pattern.fastmap);
#endif

    if (bin_data)          free(bin_data);

    if (quiet < 1 && sig >= 0 && !read_file
     && pd && !pcap_stats(pd, &s))
        printf("%u received, %u dropped\n", s.ps_recv, s.ps_drop);

    if (pd)      pcap_close(pd);
    if (pd_dump) pcap_dump_close(pd_dump);

#if defined(_WIN32)
    if (delay_socket) closesocket(delay_socket);
    if (want_delay)   WSACleanup();
    if (usedev)       free(usedev);
#endif

    exit(sig);
}

#if defined(_WIN32)
int8_t win32_initwinsock(void) {
    WORD wVersionRequested = MAKEWORD(2, 0);
    WSADATA wsaData;

    if (WSAStartup(wVersionRequested, &wsaData)) {
        perror("unable to initialize winsock");
        return 0;
    }

    // we want at least major version 2
    if (LOBYTE(wsaData.wVersion) < 2) {
        fprintf(stderr, "unable to find winsock 2.0 or greater (found %u.%u)\n",
                LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
        WSACleanup();
        return 0;
    }

    return 1;
}

void win32_listdevices(void) {
    uint32_t i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate device list");
        clean_exit(-1);
    }

    printf("idx\tdev\n");
    printf("---\t---\n");

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%2u:\t%s", ++i, d->name);

        if (d->description)
            printf(" (%s)\n", d->description);
    }

    pcap_freealldevs(alldevs);
}

char *win32_usedevice(const char *index) {
    int32_t idx = atoi(index), i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;

    if (idx <= 0) {
        perror("invalid device index");
        clean_exit(-1);
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate devices");
        clean_exit(-1);
    }

    for (d = alldevs; d != NULL && i != idx; d = d->next)
        if (++i == idx)
            dev = _strdup(d->name);

    if (i <= 0) {
        perror("no known devices");
        clean_exit(-1);
    }

    if (i != idx) {
        perror("unknown device specified");
        clean_exit(-1);
    }

    pcap_freealldevs(alldevs);

    return dev;
}
#endif



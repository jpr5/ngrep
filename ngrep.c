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
#include <nettypes.h>
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

#if USE_PCRE
#include "pcre-5.0/pcre.h"
#else
#include "regex-0.12/regex.h"
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ngrep.h"


#if defined(_WIN32)
#define strcasecmp stricmp
struct timeval delay_tv;
FD_SET delay_fds;
SOCKET delay_socket = 0;
#endif

static char rcsver[] = "$Revision$";

unsigned snaplen = 65535, limitlen = 65535, promisc = 1, to = 1000;
unsigned show_empty = 0, show_hex = 0, quiet = 0;
unsigned match_after = 0, keep_matching = 0;
unsigned invert_match = 0, bin_match = 0;
unsigned matches = 0, max_matches = 0;
unsigned live_read = 1, want_delay = 0;
unsigned no_dropprivs = 0;

char nonprint_char = '.';

char pc_err[PCAP_ERRBUF_SIZE];
#if USE_PCRE
int err_offset;
char *re_err = NULL;
#else
const char *re_err = NULL;
#endif

unsigned re_match_word = 0, re_ignore_case = 0, re_multiline_match = 1;

#if USE_PCRE
pcre *pattern = NULL;
pcre_extra *pattern_extra = NULL;
#else
struct re_pattern_buffer pattern;
#endif

char *match_data = NULL, *bin_data = NULL, *filter = NULL, *filter_file = NULL;
int (*match_func)() = &blank_match_func;
void (*dump_func)(char *, unsigned) = &dump_formatted;
unsigned match_len = 0;

struct bpf_program pcapfilter;
struct in_addr net, mask;
pcap_t *pd = NULL;
char *usedev = NULL;
unsigned link_offset;

char *read_file = NULL, *dump_file = NULL;
pcap_dumper_t *pd_dump = NULL;

struct timeval prev_ts = {0, 0}, prev_delay_ts = {0,0};
void (*print_time)() = NULL, (*dump_delay)() = dump_delay_proc_init;

unsigned ws_row, ws_col = 80, ws_col_forced = 0;


int main(int argc, char **argv) {
    int c;

    signal(SIGINT,   clean_exit);
    signal(SIGABRT,  clean_exit);

#if !defined(_WIN32)
    signal(SIGQUIT,  clean_exit);
    signal(SIGPIPE,  clean_exit);
    signal(SIGWINCH, update_windowsize);
#endif

    while ((c = getopt(argc, argv, "LhXViwqpevxlDtTRMs:n:c:d:A:I:O:S:P:F:W:")) != EOF) {
        switch (c) {
            case 'W': {
                if (!strcasecmp(optarg, "normal"))
                    dump_func = &dump_formatted;
                else if (!strcasecmp(optarg, "byline"))
                    dump_func = &dump_byline;
                else if (!strcasecmp(optarg, "none"))
                    dump_func = &dump_unwrapped;
                else {
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
            case 's':
                snaplen = atoi(optarg);
                break;
            case 'M':
                re_multiline_match = 0;
                break;
            case 'R':
                no_dropprivs = 1;
                break;
            case 'T':
                print_time = &print_time_diff;
#if defined(_WIN32)
                prev_ts.tv_sec  = time(NULL);
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

#if !defined(_WIN32)
        drop_privs();
#endif

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

#if !defined(_WIN32)
        drop_privs();
#endif

        if (pcap_lookupnet(dev, &net.s_addr, &mask.s_addr, pc_err) == -1) {
            perror(pc_err);
            memset(&net, 0, sizeof(net));
            memset(&mask, 0, sizeof(mask));
        }

        if (!quiet) {
            printf("interface: %s", dev);
            if (net.s_addr && mask.s_addr) {
                printf(" (%s/", inet_ntoa(net));
                printf("%s)", inet_ntoa(mask));
            }
            printf("\n");
        }
    }

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
        char *default_filter = "ip";

        if (pcap_compile(pd, &pcapfilter, default_filter, 0, mask.s_addr)) {
            pcap_perror(pd, "pcap compile");
            clean_exit(-1);
        }
    }

    if (filter && !quiet)
        printf("filter: %s\n", filter);

    if (pcap_setfilter(pd, &pcapfilter)) {
        pcap_perror(pd, "pcap set");
        clean_exit(-1);
    }

    if (match_data) {
        if (bin_match) {
            unsigned i = 0, n;
            char *s, *d;
            unsigned len;

            if (re_match_word || re_ignore_case) {
                fprintf(stderr, "fatal: regex switches are incompatible with binary matching\n");
                clean_exit(-1);
            }

            len = (unsigned)strlen(match_data);
            if (len % 2 != 0 || !strishex(match_data)) {
                fprintf(stderr, "fatal: invalid hex string specified\n");
                clean_exit(-1);
            }

            bin_data = malloc(len / 2);
            memset(bin_data, 0, len / 2);
            d = bin_data;

            if ((s = strchr(match_data, 'x')))
                len -= (unsigned)(++s - match_data - 1);
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
            unsigned pcre_options = PCRE_UNGREEDY;

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
                char *s;
                unsigned i;

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

        if (!quiet && match_data && strlen(match_data))
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
}


void process(u_char *d, struct pcap_pkthdr *h, u_char *p) {
    struct ip *ip_packet = (struct ip *)(p + link_offset);

#if defined(AIX)
#undef ip_hl
    unsigned ip_hl = ip_packet->ip_ff.ip_fhl*4;
#else
    unsigned ip_hl = ip_packet->ip_hl*4;
#endif

    unsigned ip_off      = ntohs(ip_packet->ip_off);
    unsigned fragmented  = ip_off & (IP_MF | IP_OFFMASK);
    unsigned frag_offset = fragmented?(ip_off & IP_OFFMASK) * 8:0;

    char *data;
    unsigned len;

    switch (ip_packet->ip_p) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (struct tcphdr *)(((char *)ip_packet) + ip_hl);
            unsigned tcphdr_offset = fragmented?0:(tcp->th_off * 4);

            if (!quiet) {
                printf("#");
                fflush(stdout);
            }

            data = ((char*)tcp) + tcphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + tcphdr_offset;
            else len = h->caplen - link_offset - ip_hl - tcphdr_offset;

            if (len > limitlen) len = limitlen;

            if (((len || show_empty) && (((int)(*match_func)(data, len)) != invert_match))
                || keep_matching) {

                if (!live_read && want_delay)
                    dump_delay(h);

                printf("\nT ");

                if (print_time)
                    print_time(h);

                if (tcphdr_offset || !frag_offset) {
                    printf("%s:%u -", inet_ntoa(ip_packet->ip_src), ntohs(tcp->th_sport));
                    printf("> %s:%u", inet_ntoa(ip_packet->ip_dst), ntohs(tcp->th_dport));
                    printf(" [%s%s%s%s%s%s%s%s]",
                           (tcp->th_flags & TH_ACK)?"A":"",
                           (tcp->th_flags & TH_SYN)?"S":"",
                           (tcp->th_flags & TH_RST)?"R":"",
                           (tcp->th_flags & TH_FIN)?"F":"",
                           (tcp->th_flags & TH_URG)?"U":"",
                           (tcp->th_flags & TH_PUSH)?"P":"",
                           (tcp->th_flags & TH_ECE)?"E":"",
                           (tcp->th_flags & TH_CWR)?"C":"");
                } else {
                    printf("%s -", inet_ntoa(ip_packet->ip_src));
                    printf("> %s", inet_ntoa(ip_packet->ip_dst));
                }

                if (fragmented)
                    printf(" %s%u@%u:%u\n", frag_offset?"+":"", ntohs(ip_packet->ip_id),
                           frag_offset, len);
                else printf("\n");

                if (pd_dump)
                    pcap_dump((u_char*)pd_dump, h, p);

                if (quiet < 2)
                    dump_func(data, len);
            }
        } break;

        case IPPROTO_UDP: {
            struct udphdr* udp = (struct udphdr *)(((char *)ip_packet) + ip_hl);
            unsigned udphdr_offset = (fragmented)?0:sizeof(struct udphdr);

            if (!quiet) {
                printf("#");
                fflush(stdout);
            }

            data = ((char*)udp) + udphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + udphdr_offset;
            else len = h->caplen - link_offset - ip_hl - udphdr_offset;

            if (len > limitlen) len = limitlen;

            if (((len || show_empty) && (((int)(*match_func)(data, len)) != invert_match))
                || keep_matching) {

                if (!live_read && want_delay)
                    dump_delay(h);

                printf("\nU ");

                if (print_time)
                    print_time(h);

                if (udphdr_offset || !frag_offset) {
#if HAVE_DUMB_UDPHDR
                    printf("%s:%u -", inet_ntoa(ip_packet->ip_src), ntohs(udp->source));
                    printf("> %s:%u", inet_ntoa(ip_packet->ip_dst), ntohs(udp->dest));
#else
                    printf("%s:%u -", inet_ntoa(ip_packet->ip_src), ntohs(udp->uh_sport));
                    printf("> %s:%u", inet_ntoa(ip_packet->ip_dst), ntohs(udp->uh_dport));
#endif
                } else {
                    printf("%s -", inet_ntoa(ip_packet->ip_src));
                    printf("> %s", inet_ntoa(ip_packet->ip_dst));
                }

                if (fragmented)
                    printf(" %s%u@%u:%u\n", frag_offset?"+":"", ntohs(ip_packet->ip_id),
                           frag_offset, len);
                else printf("\n");

                if (pd_dump)
                    pcap_dump((u_char*)pd_dump, h, p);

                if (quiet < 2)
                    dump_func(data, len);
            }
        } break;

        case IPPROTO_ICMP: {
            struct icmp* ic = (struct icmp *)(((char *)ip_packet) + ip_hl);
            unsigned icmphdr_offset = fragmented?0:4;

            if (!quiet) {
                printf("#");
                fflush(stdout);
            }

            data = ((char*)ic) + icmphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + icmphdr_offset;
            else len = h->caplen - link_offset - ip_hl - icmphdr_offset;

            if (len > limitlen) len = limitlen;

            if (((len || show_empty) && (((int)(*match_func)(data, len)) != invert_match))
                || keep_matching) {

                if (!live_read && want_delay)
                    dump_delay(h);

                printf("\nI ");

                if (print_time)
                    print_time(h);

                printf("%s -", inet_ntoa(ip_packet->ip_src));
                printf("> %s", inet_ntoa(ip_packet->ip_dst));

                if (icmphdr_offset || !frag_offset)
                    printf(" %u:%u", ic->icmp_type, ic->icmp_code);

                if (fragmented)
                    printf(" %s%u@%u:%u\n", frag_offset?"+":"", ntohs(ip_packet->ip_id),
                           frag_offset, len);
                else printf("\n");

                if (pd_dump)
                    pcap_dump((u_char*)pd_dump, h, p);

                if (quiet < 2)
                    dump_func(data, len);
            }
        } break;

        case IPPROTO_IGMP: {
            struct igmp* ig = (struct igmp *)(((char *)ip_packet) + ip_hl);
            unsigned igmphdr_offset = fragmented?0:4;

            if (!quiet) {
                printf("#");
                fflush(stdout);
            }

            data = ((char*)ig) + igmphdr_offset;

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl + igmphdr_offset;
            else len = h->caplen - link_offset - ip_hl - igmphdr_offset;

            if (len > limitlen) len = limitlen;

            if (((len || show_empty) && (((int)(*match_func)(data, len)) != invert_match))
                || keep_matching) {

                if (!live_read && want_delay)
                    dump_delay(h);

                printf("\nG ");

                if (print_time)
                    print_time(h);

                printf("%s -", inet_ntoa(ip_packet->ip_src));
                printf("> %s", inet_ntoa(ip_packet->ip_dst));

                if (igmphdr_offset || !frag_offset)
                    printf(" %u:%u", ig->igmp_type, ig->igmp_code);

                if (fragmented)
                    printf(" %s%u@%u:%u\n", frag_offset?"+":"", ntohs(ip_packet->ip_id),
                           frag_offset, len);
                else printf("\n");

                if (pd_dump)
                    pcap_dump((u_char*)pd_dump, h, p);

                if (quiet < 2)
                    dump_func(data, len);
            }
        } break;

        default: {
            data = (char*)(((char*)ip_packet) + ip_hl);

            if ((len = ntohs(ip_packet->ip_len)) < h->caplen)
                len -= ip_hl;
            else len = h->caplen - link_offset - ip_hl;

            if (len > limitlen) len = limitlen;

            if (((len || show_empty) && (((int)(*match_func)(data, len)) != invert_match))
                || keep_matching) {

                if (!live_read && want_delay)
                    dump_delay(h);

                printf("\n? ");

                if (print_time)
                    print_time(h);

                printf("%s -", inet_ntoa(ip_packet->ip_src));
                printf("> %s ", inet_ntoa(ip_packet->ip_dst));

                printf("[proto %u]\n", ip_packet->ip_p);

                if (pd_dump)
                    pcap_dump((u_char*)pd_dump, h, p);

                if (quiet < 2)
                    dump_func(data, len);
            }
        } break;

    }

    if (max_matches && matches >= max_matches)
        clean_exit(0);

    if (match_after && keep_matching)
        keep_matching--;
}


int re_match_func(char *data, unsigned len) {
#if USE_PCRE
    switch(pcre_exec(pattern, 0, data, (int)len, 0, 0, 0, 0)) {
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
    switch (re_search(&pattern, data, (int)len, 0, len, 0)) {
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


int bin_match_func(char *data, unsigned len) {
    signed stop = len - match_len;
    unsigned i = 0;

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


int blank_match_func(char *data, unsigned len) {
    if (max_matches)
        matches++;

    return 1;
}


void dump_byline(char *data, unsigned len) {
    if (len > 0) {
        const char *s = data;

        while (s < data + len) {
            printf("%c", (*s == '\n' || isprint((unsigned char)*s))? (char)*s : nonprint_char);
            s++;
        }

        printf("\n");
    }
}

void dump_unwrapped(char *data, unsigned len) {
    if (len > 0) {
        const char *s = data;

        while (s < data + len) {
            printf("%c", isprint((unsigned char)*s) ? (char)*s : nonprint_char);
            s++;
        }

        printf("\n");
    }
}

void dump_formatted(char *data, unsigned len) {
    if (len > 0) {
        unsigned width = show_hex?16:(ws_col-5);
        char *str = data;
        unsigned j, i = 0;

        while (i < len) {
            printf("  ");

            if (show_hex)
                for (j = 0; j < width; j++) {
                    if (i+j < len)
                        printf("%02x ", (unsigned char)str[j]);
                    else printf("   ");

                    if ((j+1) % (width/2) == 0)
                        printf("   ");
                }

            for (j = 0; j < width; j++)
                if (i+j < len)
                    printf("%c", isprint((unsigned char)str[j]) ? (char)str[j] : nonprint_char);
                else printf(" ");

            str += width;
            i += j;

            printf("\n");
        }
    }
}

char *get_filter_from_string(char *str) {
    char *mine;
    unsigned len;

    if (!str || !*str)
        return NULL;

    len = (unsigned)strlen(str);

    {
        char *s;
        for (s = str; *s; s++)
            if (*s == '\r' || *s == '\n')
                *s = ' ';
    }

    if (!(mine = (char*)malloc(len + sizeof(IP_ONLY))))
        return NULL;

    memset(mine, 0, len + sizeof(IP_ONLY));

    sprintf(mine, IP_ONLY, str);

    return mine;
}

char *get_filter_from_argv(char **argv) {
    char **arg = argv, *theirs, *mine;
    char *from, *to;
    unsigned len = 0;

    if (!*arg)
        return NULL;

    while (*arg)
        len += (unsigned)strlen(*arg++) + 1;

    if (!(theirs = (char*)malloc(len + 1)) ||
        !(mine = (char*)malloc(len + sizeof(IP_ONLY))))
        return NULL;

    memset(theirs, 0, len + 1);
    memset(mine, 0, len + sizeof(IP_ONLY));

    arg = argv;
    to = theirs;

    while ((from = *arg++)) {
        while ((*to++ = *from++));
        *(to-1) = ' ';
    }

    sprintf(mine, IP_ONLY, theirs);

    free(theirs);
    return mine;
}


int strishex(char *str) {
    char *s;
    if ((s = strchr(str, 'x')))
        s++;
    else s = str;

    while (*s)
        if (!isxdigit(*s++))
            return 0;

    return 1;
}


void print_time_absolute(struct pcap_pkthdr *h) {
    struct tm *t = localtime((const time_t *)&h->ts.tv_sec);

    printf("%02d/%02d/%02d %02d:%02d:%02d.%06d ",
           t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour,
           t->tm_min, t->tm_sec, h->ts.tv_usec);
}

void print_time_diff(struct pcap_pkthdr *h) {
    unsigned secs, usecs;

    secs = h->ts.tv_sec - prev_ts.tv_sec;
    if (h->ts.tv_usec >= prev_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_ts.tv_usec - h->ts.tv_usec);
    }

    printf("+%u.%06d ", secs, usecs);

    prev_ts.tv_sec = h->ts.tv_sec;
    prev_ts.tv_usec = h->ts.tv_usec;
}

void dump_delay_proc_init(struct pcap_pkthdr *h) {
    dump_delay = &dump_delay_proc;

    prev_delay_ts.tv_sec = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;

    dump_delay(h);
}

void dump_delay_proc(struct pcap_pkthdr *h) {
    unsigned secs, usecs;

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

        delay_tv.tv_sec = secs;
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

    prev_delay_ts.tv_sec = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;
}

#if !defined(_WIN32)
void update_windowsize(int e) {
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

    if (no_dropprivs || !USE_DROPPRIVS)
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

void usage(int e) {
    printf("usage: ngrep <-LhXViwqpevxlDtTRM> <-IO pcap_dump> <-n num> <-d dev> <-A num>\n"
           "             <-s snaplen> <-S limitlen> <-W normal|byline|none> <-c cols>\n"
           "             <-P char> <-F file> <match expression> <bpf filter>\n");

    exit(e);
}


void version(void) {
    printf("ngrep: V%s, %s\n", VERSION, rcsver);
    exit(0);
}


void clean_exit(int sig) {
    struct pcap_stat s;
    if (!quiet && sig >= 0) printf("exit\n");

#if USE_PCRE
    if (pattern) pcre_free(pattern);
    if (pattern_extra) pcre_free(pattern_extra);
#else
    if (pattern.translate) free(pattern.translate);
    if (pattern.fastmap) free(pattern.fastmap);
#endif

    if (bin_data) free(bin_data);

    if (!quiet && sig >= 0 && !read_file &&
        pd && !pcap_stats(pd, &s))
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
int win32_initwinsock(void) {
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
    unsigned i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate device list");
        clean_exit(-1);
    }

    printf("interface\tdevice\n");
    printf("---------\t------\n");

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%9d\t%s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    pcap_freealldevs(alldevs);
}

char *win32_usedevice(const char *index) {
    unsigned idx = atoi(index), i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;

    if (idx == 0) {
        perror("invalid device index");
        clean_exit(-1);
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate devices");
        clean_exit(-1);
    }

    for (d = alldevs; d != NULL; d = d->next)
        if (++i == idx)
            dev = _strdup(d->name);

    if (i == 0) {
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



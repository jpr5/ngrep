/*
 * Copyright (c) 2014  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#define VERSION "1.46.1"

/*
 * We cache the standard frame sizes here to save us time and
 * additional dependencies on more operating system include files.
 */

#define ETHHDR_SIZE 14
#define TOKENRING_SIZE 22
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#define ISDNHDR_SIZE 16
#define IEEE80211HDR_SIZE 32
#define PFLOGHDR_SIZE 48
#define VLANHDR_SIZE 4

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP      0x0800
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6      0x86dd
#endif

#define EXTRACT_16BITS(p) \
  ((uint16_t)((uint16_t)*((const uint8_t *)(p) + 0) << 8 | \
	       (uint16_t)*((const uint8_t *)(p) + 1)))

/*
 * Default patterns for BPF and regular expression filters.
 *
 * When targeting IP frames with a BPF filter, optionally-present VLAN frames
 * will be excluded by default, thus any IP traffic on a VLAN'd network is
 * invisible to ngrep by default.  This requires the user to specify "vlan"
 * every time they are on a VLAN'd network, which gets irritating fast.
 *
 * In turn, this leads to a surprising behavior when working with pcap dump
 * files created from a "vlan" filter: reading and re-processing them requires
 * the same "vlan" filter to be specified, otherwise the traffic will be
 * invisible.  IOW, when the dump reader is targeting IP traffic in the dump but
 * doesn't know (or remember) the "vlan" filter was specified, they will see
 * nothing -- and mistakenly blame ngrep.
 *
 * While the behavior is technically consistent, to the user it can be
 * surprising, confusing, and therefore Dumb As Shit.  For convenience' sake, we
 * fix this for them by including VLAN (optionally) back into the stream
 * targeting IP traffic, and compensating for the variable offset in the packet
 * decoder.
 */

#if USE_IPv6
#define BPF_FILTER_IP_TYPE  "(ip || ip6)"
#else
#define BPF_FILTER_IP_TYPE  "(ip)"
#endif

#define BPF_FILTER_IP       "(" BPF_FILTER_IP_TYPE " || (vlan && " BPF_FILTER_IP_TYPE "))"

#define BPF_FILTER_OTHER    "( %s) and "
#define BPF_MAIN_FILTER     BPF_FILTER_OTHER BPF_FILTER_IP

#define WORD_REGEX "((^%s\\W)|(\\W%s$)|(\\W%s\\W))"

/*
 * For retarded operating systems like Solaris that don't have this,
 * when everyone else does.  Good job, Sun!
 */

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

/*
 * "Newer" flags that older operating systems don't yet recognize.
 */

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif


/*
 * Single-char packet "ident" flags.
 */

typedef enum {
    TCP = 'T', UDP = 'U', ICMP = 'I', ICMPv6 = 'I', IGMP = 'G', UNKNOWN = '?'
} netident_t;

/*
 * Prototypes function signatures.
 */

void process(u_char *, struct pcap_pkthdr *, u_char *);

void version(void);
void usage(int8_t);
void update_windowsize(int32_t);
void clean_exit(int32_t);

void dump_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, uint32_t,
                 const char *, const char *, uint16_t, uint16_t, uint8_t,
                 uint16_t, uint8_t, uint16_t, uint32_t);

void dump_unwrapped(unsigned char *, uint32_t, uint16_t, uint16_t);
void dump_formatted(unsigned char *, uint32_t, uint16_t, uint16_t);
void dump_byline   (unsigned char *, uint32_t, uint16_t, uint16_t);

void dump_delay_proc_init(struct pcap_pkthdr *);
void dump_delay_proc     (struct pcap_pkthdr *);

int8_t re_match_func   (unsigned char *, uint32_t, uint16_t *, uint16_t *);
int8_t bin_match_func  (unsigned char *, uint32_t, uint16_t *, uint16_t *);
int8_t blank_match_func(unsigned char *, uint32_t, uint16_t *, uint16_t *);

void print_time_absolute(struct pcap_pkthdr *);
void print_time_diff    (struct pcap_pkthdr *);
void print_time_offset  (struct pcap_pkthdr *);

char *get_filter_from_string(char *);
char *get_filter_from_argv  (char **);

uint8_t strishex(char *);

#if !defined(_WIN32)
void drop_privs(void);
#endif

#if defined(_WIN32)
int8_t win32_initwinsock(void);
void win32_listdevices(void);
char *win32_usedevice(const char *);
char *win32_choosedevice(void);
#endif


struct NGREP_rtaphdr_t {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};


/*
 * ANSI color/hilite stuff.
 */

const char ANSI_red[]  = "\33[01;31m";
const char ANSI_bold[] = "\33[01m";

const char *ANSI_hilite = ANSI_red;
const char  ANSI_off[]  = "\33[00m";



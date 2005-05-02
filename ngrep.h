/*
 * $Id$
 *
 * Copyright (c) 2005  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#define VERSION "1.44"

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

/*
 * Default patterns for BPF and regular expression filters.
 */

#if USE_IPv6
#define BPF_FILTER_IP       "(ip or ip6)"
#else
#define BPF_FILTER_IP       "(ip)"
#endif

#define BPF_FILTER_OTHER    " and ( %s)"
#define BPF_MAIN_FILTER     BPF_FILTER_IP BPF_FILTER_OTHER

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
void clean_exit(signed int);
void usage(signed int);
void version(void);

char *get_filter_from_string(char *);
char *get_filter_from_argv(char **);

int re_match_func(unsigned char *, unsigned int);
int bin_match_func(unsigned char *, unsigned int);
int blank_match_func(unsigned char *, unsigned int);

void dump_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, unsigned int,
                 const char *, const char *, uint16_t, uint16_t, uint8_t,
                 uint16_t, uint8_t, uint16_t, uint32_t);

void dump_unwrapped(unsigned char *, unsigned int);
void dump_byline(unsigned char *, unsigned int);
void dump_formatted(unsigned char *, unsigned int);

int strishex(char *);

void print_time_absolute(struct pcap_pkthdr *);
void print_time_diff(struct pcap_pkthdr *);

void dump_delay_proc_init(struct pcap_pkthdr *);
void dump_delay_proc(struct pcap_pkthdr *);

#if !defined(_WIN32)
void update_windowsize(signed int);
void drop_privs(void);
#endif

#if defined(_WIN32)
int win32_initwinsock(void);
void win32_listdevices(void);
char *win32_usedevice(const char *);
#endif

/*
 * $Id$
 *
 * Copyright (c) 2006  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#define VERSION "1.46-CVS"

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



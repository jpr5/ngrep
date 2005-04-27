
/*
 * $Id$
 *
 * Because Windows standard headers are woefully inadequate for (real)
 * network application development, and because I'm basically lazy, I
 * created this header as a container for the types ngrep needs.
 *
 * These include standard types like u*int*_t's, as well as network
 * protocol-specific structures and types.
 */

typedef unsigned char      u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int       u_int32_t;

typedef unsigned char      uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int       uint32_t;


#define IP_RF 0x8000                            /* reserved fragment flag */
#define IP_DF 0x4000                            /* dont fragment flag */
#define IP_MF 0x2000                            /* more fragments flag */
#define IP_OFFMASK 0x1fff                       /* mask for fragmenting bits */

struct ip {
    u_int8_t ip_hl:4;                   /* header length */
    u_int8_t ip_v:4;                    /* version */
    u_int8_t ip_tos;                            /* type of service */
    u_int16_t ip_len;                                   /* total length */
    u_int16_t ip_id;                                    /* identification */
    u_int16_t ip_off;                                   /* fragment offset field */
    u_int8_t ip_ttl;                            /* time to live */
    u_int8_t ip_p;                                      /* protocol */
    u_int16_t ip_sum;                                   /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
};

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

typedef u_int32_t tcp_seq;

struct tcphdr {
    u_int16_t th_sport;                         /* source port */
    u_int16_t th_dport;                         /* destination port */
    tcp_seq th_seq;                                     /* sequence number */
    tcp_seq th_ack;                                     /* acknowledgement number */
    u_int8_t th_x2:4;                           /* (unused) */
    u_int8_t th_off:4;                          /* data offset */
    u_int8_t th_flags;
    u_int16_t th_win;                           /* window */
    u_int16_t th_sum;                           /* checksum */
    u_int16_t th_urp;                           /* urgent pointer */
};

struct udphdr {
        u_int16_t uh_sport;                             /* source port */
    u_int16_t uh_dport;             /* destination port */
    u_int16_t uh_ulen;              /* udp length */
    u_int16_t uh_sum;               /* udp checksum */
};


struct icmp {
        u_int8_t  icmp_type;
        u_int8_t  icmp_code;
        u_int16_t icmp_cksum;

        union {
                u_int8_t ih_pptr;
                struct in_addr ih_gwaddr;
                struct ih_idseq {
                        u_int16_t icd_id;
                        u_int16_t icd_seq;
                } ih_idseq;
                u_int32_t ih_void;

                struct ih_pmtu {
                        u_int16_t ipm_void;
                        u_int16_t ipm_nextmtu;
                } ih_pmtu;

                struct ih_rtradv {
                        u_int8_t irt_num_addrs;
                        u_int8_t irt_wpa;
                        u_int16_t irt_lifetime;
                } ih_rtradv;
        } icmp_hun;
};

struct igmp {
  u_int8_t igmp_type;             /* IGMP type */
  u_int8_t igmp_code;             /* routing code */
  u_int16_t igmp_cksum;           /* checksum */
  struct in_addr igmp_group;      /* group address */
};

/*
 * Taken from arpa/namser.h, used by inet_?to?() (Win32 support).
 */

#define NS_INADDRSZ      4
#define NS_IN6ADDRSZ     16      /* IPv6 T_AAAA */
#define NS_INT16SZ       2       /* #/bytes of data in a u_int16_t */

/*
 * IPv6 and ICMPv6 declarations.
 */

/* IPv6 address */
struct UNIX_in6_addr {
    union {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    } in6_u;
};

struct ip6_hdr {
    union {
        struct ip6_hdrctl {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
          } ip6_un1;

        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */

        } ip6_ctlun;

    struct UNIX_in6_addr ip6_src;      /* source address */
    struct UNIX_in6_addr ip6_dst;      /* destination address */
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Fragment header */
struct ip6_frag {
    uint8_t   ip6f_nxt;         /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;       /* offset, reserved, and flag */
    uint32_t  ip6f_ident;       /* identification */
};

#if     BYTE_ORDER == BIG_ENDIAN
#define IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
#define IP6F_RESERVED_MASK  0x0006  /* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
#define IP6F_RESERVED_MASK  0x0600  /* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif

struct icmp6_hdr {
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */
    union {
                uint32_t  icmp6_un_data32[1]; /* type-specific field */
                uint16_t  icmp6_un_data16[2]; /* type-specific field */
                uint8_t   icmp6_un_data8[4];  /* type-specific field */
        } icmp6_dataun;
};

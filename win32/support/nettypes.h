
/* 
 * $Id$
 *
 * Because Windows standard headers are woefully inadequate for (real)
 * network application development, and because I'm basically lazy, I 
 * created this header as a container for the types ngrep needs.
 * 
 * The orginal ngrep port to Windows was completed by
 * Mike Davis <mike@eEye.com>.  Unfortunately, I wasn't able to 
 * figure out how he did the headers, so I had to redo a lot on my own.
 * Please pardon the hack.
 */

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;


#define	IP_RF 0x8000				/* reserved fragment flag */
#define	IP_DF 0x4000				/* dont fragment flag */
#define	IP_MF 0x2000				/* more fragments flag */	
#define	IP_OFFMASK 0x1fff			/* mask for fragmenting bits */

struct ip {
    u_int8_t ip_hl:4;			/* header length */
    u_int8_t ip_v:4;			/* version */
    u_int8_t ip_tos;				/* type of service */
    u_int16_t ip_len;					/* total length */
    u_int16_t ip_id;					/* identification */
    u_int16_t ip_off;					/* fragment offset field */
    u_int8_t ip_ttl;				/* time to live */
    u_int8_t ip_p;					/* protocol */
    u_int16_t ip_sum;					/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};


#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

typedef	u_int32_t tcp_seq;

struct tcphdr {
    u_int16_t th_sport;				/* source port */
    u_int16_t th_dport;				/* destination port */
    tcp_seq th_seq;					/* sequence number */
    tcp_seq th_ack;					/* acknowledgement number */
    u_int8_t th_x2:4;				/* (unused) */
    u_int8_t th_off:4;				/* data offset */
    u_int8_t th_flags;
    u_int16_t th_win;				/* window */
    u_int16_t th_sum;				/* checksum */
    u_int16_t th_urp;				/* urgent pointer */
};

struct udphdr {
	u_int16_t uh_sport;				/* source port */
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
		struct ih_idseq	{
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
/*
 * tcpkill.c
 *
 * Kill TCP connections already in progress.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcpkill.c,v 1.17 2001/03/17 08:10:43 dugsong Exp $
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>

#include "tcpkill.h"

libnet_t *l;

void
tcpkill_kill(const struct pcap_pkthdr *pcap, const u_char *pkt,
       uint32_t pcap_off, uint32_t kill_count)
{
  struct libnet_ipv4_hdr *ip;
  struct libnet_tcp_hdr *tcp;
  char ctext[64];
  uint32_t seq, win, i;

  pkt += pcap_off;

  ip = (struct libnet_ipv4_hdr *)pkt;
  if (ip->ip_p != IPPROTO_TCP)
      return;

  tcp = (struct libnet_tcp_hdr *)(pkt + (ip->ip_hl << 2));
  if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
      return;

  seq = ntohl(tcp->th_ack);
  win = ntohs(tcp->th_win);

  snprintf(ctext, sizeof(ctext), "%s:%d > %s:%d:",
       libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
       ntohs(tcp->th_sport),
       libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
       ntohs(tcp->th_dport));

  for (i = 0; i < kill_count; i++) {
      seq += (i * win);

      libnet_clear_packet(l);

      libnet_build_tcp(ntohs(tcp->th_dport), ntohs(tcp->th_sport),
               seq, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H,
               NULL, 0, l, 0);

      libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
                libnet_get_prand(LIBNET_PRu16), 0, 64,
                IPPROTO_TCP, 0, ip->ip_dst.s_addr,
                ip->ip_src.s_addr, NULL, 0, l, 0);

      if (libnet_write(l) < 0)
          fprintf(stderr, "libnet_write failed\n");

      fprintf(stderr, "%s R %u:%u(0) win 0\n", ctext, seq, seq);
  }
}

void
tcpkill_init(void)
{
  char *intf, ebuf[PCAP_ERRBUF_SIZE];
  char libnet_ebuf[LIBNET_ERRBUF_SIZE];

  if ((intf = pcap_lookupdev(ebuf)) == NULL)
      fprintf(stderr, "%s\n", ebuf);

  if ((l = libnet_init(LIBNET_RAW4, intf, libnet_ebuf)) == NULL)
      fprintf(stderr, "libnet_init failed\n");

  libnet_seed_prand(l);
}

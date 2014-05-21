#ifndef TCPKILL_H
#define TCPKILL_H

void tcpkill_init(void);
void tcpkill_kill(const struct pcap_pkthdr *pcap, const u_char *pkt, unsigned pcap_off, unsigned kill_count);

#endif

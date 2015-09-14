#ifndef TCPKILL_H
#define TCPKILL_H

void tcpkill_init(void);
void tcpkill_kill(const struct pcap_pkthdr *pcap, const u_char *pkt, uint32_t pcap_off, uint32_t kill_count);

#endif

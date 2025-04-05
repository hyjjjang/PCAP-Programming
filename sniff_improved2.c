#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IP
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->caplen - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

            printf("\n==== Captured TCP Packet ====\n");
            printf("Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("IP From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("IP To  : %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("TCP Dst Port: %d\n", ntohs(tcp->tcp_dport));

            if (payload_len > 0) {
                printf("Payload (%d bytes):\n", payload_len);
                for (int i = 0; i < payload_len && i < 32; i++) {
                    printf("%c", isprint(payload[i]) ? payload[i] : '.');
                }
                printf("\n");
            } else {
                printf("No Payload\n");
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // Only TCP
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Step 2: Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

#include <stdio.h> 

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

typdef struct ether_header ETH_HEADER;
typedef struct ip IP_HEADER;


int main() {
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header *eth_header;
    u_char *frame;
    int frame_size;

    // Allocate memory for the frame
    frame_size = sizeof(struct ether_header) + sizeof(struct ip);
    frame = (u_char *)malloc(frame_size);
    if (frame == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Set Ethernet header fields
    eth_header = (struct ether_header *)frame;
    memset(eth_header->ether_dhost, 0xff, ETHER_ADDR_LEN); // Destination MAC address (broadcast)
    memset(eth_header->ether_shost, 0x00, ETHER_ADDR_LEN); // Source MAC address
    eth_header->ether_type = htons(ETHERTYPE_IP); // EtherType (IPv4)

    // Set IP header fields
    struct ip *ip_header = (struct ip *)(frame + sizeof(struct ether_header));
    // Set other IP header fields as needed

    // Send the frame
    if (pcap_sendpacket(handle, frame, frame_size) != 0) {
        fprintf(stderr, "Packet sending failed\n");
        return 1;
    }

    // Clean up
    free(frame);
    pcap_close(handle);

    return 0;
}

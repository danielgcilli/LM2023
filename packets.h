#ifndef PACKETS_H
#define PACKETS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h> 
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <stdint.h>

#define IO_LIMIT 1

typedef unsigned char byte;

struct __attribute__((__packed__)) ethernet_segment {
    uint8_t mac_dst[6];
    uint8_t mac_src[6];
    uint8_t protocol_type[2]; 
};
typedef struct ethernet_segment Ether;

struct __attribute__((__packed__)) ip_header {
    uint8_t version_n_IHL;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_n_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_address;
    uint32_t dst_address;
    // leaving out options and padding for SYN packet
}; 
typedef struct ip_header IP_Header;

struct __attribute__((__packed__)) tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t offset_n_reserved;
    uint8_t control_bits;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    // leaving out options for SYN packet
};
typedef struct tcp_header TCP_Header;

byte *serialize_ether(Ether *eth_frame);
byte *serialize_ip_header(IP_Header *ip_header);
byte *serialize_tcp_header(TCP_Header *tcp_header);
byte *syn_stream(byte *ether_frame, byte *ip_header, byte *tcp_header);
void update_ip_checksum(void* ip_stream);
void update_tcp_checksum(void* tcp_stream);
void update_checksums(void* packet_stream);
byte *form_packet(byte *ip_stream, byte *tcp_stream);
void fill_SYN(IP_Header *iphead, TCP_Header *tcphead, uint32_t dst_address, uint16_t dst_port);
void bin_dump(byte *stream, int numbytes, int endianess);
void hexDump(void *buffer, size_t length);

#endif
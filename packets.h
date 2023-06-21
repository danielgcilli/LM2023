#ifndef PACKETS_H
#define PACKETS_H

#include <stdint.h>

struct ethernet_segment {
    uint8_t mac_dst[6];
    uint8_t mac_src[6];
    uint8_t protocol_type[2]; 
};
typedef struct ethernet_segment ETHER;

struct ip_header {
    uint8_t version_n_IHL;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_n_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_address;
    uint32_t dst_address;
    // leaving out options and padding for SYN packet
}; 
typedef struct ip_header IP_HEADER;

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t offset_n_reserved;
    uint8_t control_bits;
    uint16_t window;
    uint16_t urgent_ptr;
    // leaving out options for SYN packet
};
typedef struct tcp_header TCP_HEADER;


#endif
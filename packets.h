#ifndef PACKETS_H
#define PACKETS_H


typedef unsigned char byte;

struct ethernet_segment {
    uint8_t mac_dst[6];
    uint8_t mac_dst[6];
    uint8_t protocol_type[2]; 
};

struct ip_segment {
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
    // no data
};

struct tcp_segment {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    
};

struct tcp_packet {

};

#endif
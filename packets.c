#include "packets.h"
#include <stddef.h> 
#include <string.h>

typedef unsigned char byte;

byte *serialize_ether(ETHER *eth_frame){
    byte *stream = (byte *) malloc(sizeof(ETHER));
    memmove(stream, eth_frame->mac_dst, 6);
    memmove(stream + 6, eth_frame->mac_src, 6);
    memmove(stream + 12, eth_frame->protocol_type, 2);
    return stream;
}

byte *serialize_ip_header(IP_HEADER *ip_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(IP_HEADER));
    memmove(stream, ip_header->version_n_IHL, sizeof(uint8_t));
    offset += 
    memmove(stream + offset, ip_header->type_of_service, sizeof(uint8_t));
    offset += 8;
    memmove(stream + offset, ip_header->total_length, 16);
    offset += 16;
    memmove(stream + offset, ip_header->id, 16);
    offset += 16;
    memmove(stream + offset, ip_header->flags_n_offset, 16);
    offset += 16;
    memmove(stream + offset, ip_header->time_to_live, sizeof(uint8_t));
    offset += 8;
    memmove(stream + offset, ip_header->protocol, sizeof(uint8_t));
    offset += 8;
    memmove(stream + offset, ip_header->header_checksum, 16);
    offset += 16;
    memmove(stream + offset, ip_header->src_address, 32);
    offset += 32;
    memmove(stream + offset, ip_header->dst_address, 32);
    offset += 32;
    return stream;
}

byte *serialize_tcp_header(TCP_HEADER *tcp_header){

}

byte *syn_stream(byte *ether_frame, byte *ip_header, byte *tcp_header){
    size_t len_eth = sizeof(ETHER), len_ip = sizeof(IP_HEADER), len_tcp = sizeof(TCP_HEADER);
    size_t total_len = len_eth + len_ip + len_tcp;
    byte *stream = (byte *) malloc(total_len);
    memmove(stream, ether_frame, len_eth);
    memmove(stream + len_eth, ip_header, len_ip);
    memmove(stream + len_eth + len_ip, tcp_header, len_tcp);
    return stream;
}

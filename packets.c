#include "packets.h"
#include <stddef.h> 
#include <string.h>

typedef unsigned char byte;

byte *serialize_ether(ETHER *eth_frame){
    byte *stream = (byte *) malloc(sizeof(ETHER));
    size_t offset = 0;
    memmove(stream, eth_frame->mac_dst, sizeof(eth_frame->mac_dst));
    offset += sizeof(eth_frame->mac_dst);
    memmove(stream + 6, eth_frame->mac_src, sizeof(eth_frame->mac_src));
    offset += sizeof(eth_frame->mac_src);
    memmove(stream + 12, eth_frame->protocol_type, sizeof(eth_frame->protocol_type));
    offset += sizeof(eth_frame->protocol_type);
    return stream;
}

byte *serialize_ip_header(IP_HEADER *ip_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(IP_HEADER));
    memmove(stream, ip_header->version_n_IHL, sizeof(ip_header->version_n_IHL));
    offset += sizeof(ip_header->version_n_IHL);
    memmove(stream + offset, ip_header->type_of_service, sizeof(ip_header->type_of_service));
    offset += sizeof(ip_header->type_of_service);
    memmove(stream + offset, ip_header->total_length, sizeof(ip_header->total_length));
    offset += sizeof(ip_header->total_length);
    memmove(stream + offset, ip_header->id, sizeof(ip_header->id));
    offset += sizeof(ip_header->id);
    memmove(stream + offset, ip_header->flags_n_offset, sizeof(ip_header->flags_n_offset));
    offset += sizeof(ip_header->flags_n_offset);
    memmove(stream + offset, ip_header->time_to_live, sizeof(ip_header->time_to_live));
    offset += sizeof(ip_header->time_to_live);
    memmove(stream + offset, ip_header->protocol, sizeof(ip_header->protocol));
    offset += sizeof(ip_header->protocol);
    memmove(stream + offset, ip_header->header_checksum, sizeof(ip_header->header_checksum));
    offset += sizeof(ip_header->header_checksum);
    memmove(stream + offset, ip_header->src_address, sizeof(ip_header->src_address));
    offset += sizeof(ip_header->src_address);
    memmove(stream + offset, ip_header->dst_address, sizeof(ip_header->dst_address));
    offset += sizeof(ip_header->dst_address);
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

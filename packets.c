#include "packets.h"
#include <stddef.h> 
#include <string.h>
#include <stdlib.h>

typedef unsigned char byte;

byte *serialize_ether(Ether *eth_frame){
    byte *stream = (byte *) malloc(sizeof(Ether));
    size_t offset = 0;
    memmove(stream, eth_frame->mac_dst, sizeof(eth_frame->mac_dst));
    offset += sizeof(eth_frame->mac_dst);
    memmove(stream + 6, eth_frame->mac_src, sizeof(eth_frame->mac_src));
    offset += sizeof(eth_frame->mac_src);
    memmove(stream + 12, eth_frame->protocol_type, sizeof(eth_frame->protocol_type));
    offset += sizeof(eth_frame->protocol_type);
    return stream;
}

byte *serialize_ip_header(IP_Header *ip_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(IP_Header));
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

byte *serialize_tcp_header(TCP_Header *tcp_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(TCP_Header));
    memmove(stream, tcp_header->src_port, sizeof(tcp_header));
    offset += sizeof(tcp_header);
    memmove(stream + offset, tcp_header->dst_port, sizeof(tcp_header->dst_port));
    offset += sizeof(tcp_header->dst_port);
    memmove(stream + offset, tcp_header->sequence_num, sizeof(tcp_header->sequence_num));
    offset += sizeof(tcp_header->sequence_num);
    memmove(stream + offset, tcp_header->ack_num, sizeof(tcp_header->ack_num));
    offset += sizeof(tcp_header->ack_num);
    memmove(stream + offset, tcp_header->offset_n_reserved, sizeof(tcp_header->offset_n_reserved));
    offset += sizeof(tcp_header->offset_n_reserved);
    memmove(stream + offset, tcp_header->control_bits, sizeof(tcp_header->control_bits));
    offset += sizeof(tcp_header->control_bits);
    memmove(stream + offset, tcp_header->window, sizeof(tcp_header->window));
    offset += sizeof(tcp_header->window);
    memmove(stream + offset, tcp_header->urgent_ptr, sizeof(tcp_header->urgent_ptr));
    return stream;
}

byte *syn_stream(byte *ether_frame, byte *ip_header, byte *tcp_header){
    size_t len_eth = sizeof(Ether), len_ip = sizeof(IP_Header), len_tcp = sizeof(TCP_Header);
    size_t total_len = len_eth + len_ip + len_tcp;
    byte *stream = (byte *) malloc(total_len);
    memmove(stream, ether_frame, len_eth);
    memmove(stream + len_eth, ip_header, len_ip);
    memmove(stream + len_eth + len_ip, tcp_header, len_tcp);
    return stream;
}

int update_dst_ip(IP_Header ip_header, uint32_t new_ip) {

}

uint32_t calc_tcp_checksum(TCP_Header tcp_header) {
    uint16_t version_IHL_TOS;
    version_IHL_TOS 
}

uint32_t calc_ip_checksum(IP_Header ip_header) {

}

/* specify the endianess OF THE SYSTEM */
void bin_dump(byte *stream, int numbytes, int endianess){
    if(endianess == LITTLE_ENDIAN){
        for(int i = 0; i < numbytes; i ++){
            byte chunk = *(stream + i);
            for(int b = 7; b >= 0; b --){
                (chunk & (1 << b)) ? printf("1") : printf("0");
            }
            printf(" ");
        }
        printf("\n");
    }else{ //big endian
        for(int i = numbytes - 1; i >= 0; i --){
            byte chunk = *(stream + i);
            for(int b = 7; b >= 0; b --){
                (chunk & (1 << b)) ? printf("1") : printf("0");
            }
            printf(" ");
        }
        printf("\n");
    }
}
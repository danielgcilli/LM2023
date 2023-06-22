#include "packets.h"

byte *serialize_ip_header(IP_Header *ip_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(IP_Header));
    memmove(stream, &ip_header->version_n_IHL, sizeof(ip_header->version_n_IHL));
    offset += sizeof(ip_header->version_n_IHL);
    memmove(stream + offset, &ip_header->type_of_service, sizeof(ip_header->type_of_service));
    offset += sizeof(ip_header->type_of_service);
    uint16_t _total_length = htons(ip_header->total_length);
    memmove(stream + offset, &_total_length, sizeof(ip_header->total_length));
    offset += sizeof(ip_header->total_length);
    uint16_t _id = htons(ip_header->id);
    memmove(stream + offset, &_id, sizeof(ip_header->id));
    offset += sizeof(ip_header->id);
    uint16_t _flags_n_offset = htons(ip_header->flags_n_offset);
    memmove(stream + offset, &_flags_n_offset, sizeof(ip_header->flags_n_offset));
    offset += sizeof(ip_header->flags_n_offset);
    memmove(stream + offset, &ip_header->time_to_live, sizeof(ip_header->time_to_live));
    offset += sizeof(ip_header->time_to_live);
    memmove(stream + offset, &ip_header->protocol, sizeof(ip_header->protocol));
    offset += sizeof(ip_header->protocol);
    uint16_t _checksum = htons(ip_header->checksum);
    memmove(stream + offset, &_checksum, sizeof(ip_header->checksum));
    offset += sizeof(ip_header->checksum);
    uint32_t _src_address = htonl(ip_header->src_address);
    memmove(stream + offset, &_src_address, sizeof(ip_header->src_address));
    offset += sizeof(ip_header->src_address);
    uint32_t _dst_address = htonl(ip_header->dst_address);
    memmove(stream + offset, &_dst_address, sizeof(ip_header->dst_address));
    offset += sizeof(ip_header->dst_address);
    return stream;
}

byte *serialize_tcp_header(TCP_Header *tcp_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(TCP_Header));
    memmove(stream, &tcp_header->src_port, sizeof(tcp_header));
    offset += sizeof(tcp_header);
    memmove(stream + offset, &tcp_header->dst_port, sizeof(tcp_header->dst_port));
    offset += sizeof(tcp_header->dst_port);
    memmove(stream + offset, &tcp_header->sequence_num, sizeof(tcp_header->sequence_num));
    offset += sizeof(tcp_header->sequence_num);
    memmove(stream + offset, &tcp_header->ack_num, sizeof(tcp_header->ack_num));
    offset += sizeof(tcp_header->ack_num);
    memmove(stream + offset, &tcp_header->offset_n_reserved, sizeof(tcp_header->offset_n_reserved));
    offset += sizeof(tcp_header->offset_n_reserved);
    memmove(stream + offset, &tcp_header->control_bits, sizeof(tcp_header->control_bits));
    offset += sizeof(tcp_header->control_bits);
    memmove(stream + offset, &tcp_header->window, sizeof(tcp_header->window));
    offset += sizeof(tcp_header->window);
    memmove(stream + offset, &tcp_header->urgent_ptr, sizeof(tcp_header->urgent_ptr));
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

/*
@brief  Updates checksum of a stream of the ip packet
@param  ip_stream: a buffer pointer to a stream of the ip packet header
@retval 0 on success or appropriate error
*/
void update_ip_checksum(void* ip_stream) {
    const int CHECKSUM_OFFSET = 10;
    // check if buffer pointer is null
    if (ip_stream == NULL) {
        perror("IP Stream is NULL");
        exit(EXIT_FAILURE);
    }
    uint16_t ip_checksum = 0;
    // do not include checksum in calculation so set it to 0
    memset(ip_stream + CHECKSUM_OFFSET, ip_checksum, sizeof(ip_checksum));
    // iterate through packet and calculate checksum
    uint16_t* curr_val = ip_stream;
    for (long unsigned int i = 0; i < sizeof(IP_Header); i += 2) {
        ip_checksum += *curr_val;
        curr_val += 2;
    }
    // remove carryover
    ip_checksum++;
    // negate
    ip_checksum = ~ip_checksum;
    memset(ip_stream + CHECKSUM_OFFSET, ip_checksum, sizeof(ip_checksum));
}

/*
@brief  Updates checksum of a stream of the tcp packet
@param  tcp_stream: a buffer pointer to a stream of the tcp packet header
@retval 0 on success or appropriate error
*/
// TODO: Update to correct values
void update_tcp_checksum(void* tcp_stream) {
    const int CHECKSUM_OFFSET = 16;
    // check if buffer pointer is null
    if (tcp_stream == NULL) {
        perror("TCP Stream is NULL");
        exit(EXIT_FAILURE);
    }
    uint16_t tcp_checksum = 0;
    // do not include checksum in calculation so set it to 0
    memset(tcp_stream + CHECKSUM_OFFSET, tcp_checksum, sizeof(tcp_checksum));
    // iterate through packet and calculate checksum
    uint16_t* curr_val = tcp_stream;
    for (long unsigned int i = 0; i < sizeof(TCP_Header); i += 2) {
        tcp_checksum += *curr_val;
        curr_val += 2;
    }
    // remove carryover
    tcp_checksum++;
    // negate
    tcp_checksum = ~tcp_checksum;
    memset(tcp_stream + CHECKSUM_OFFSET, tcp_checksum, sizeof(tcp_checksum));
}

/*
@brief  Updates checksum of a stream of the tcp/ip packet
@param  ip_stream: a buffer pointer to a stream of the tcp/ip packet
@retval 0 on success or appropriate error
*/
void update_checksums(void* packet_stream) {
    if (packet_stream == NULL) {
        perror("Packet Stream is NULL");
        exit(EXIT_FAILURE);
    }
    void* ip_stream = packet_stream;
    void* tcp_stream = packet_stream + sizeof(IP_Header);
    update_ip_checksum(ip_stream);
    update_tcp_checksum(tcp_stream);
}

byte *form_packet(byte *ip_stream, byte *tcp_stream) {
    size_t len_ip = sizeof(IP_Header);
    size_t len_tcp = sizeof(TCP_Header);
    byte *result = (byte *) malloc(len_ip + len_tcp);
    memmove(result, ip_stream, len_ip);
    memmove(result + len_ip, tcp_stream, len_tcp);
    return result;
}

void fill_SYN(IP_Header *iphead, TCP_Header *tcphead, uint32_t dst_address, uint16_t dst_port){
    iphead->version_n_IHL = 0x45;
    iphead->type_of_service = 0x0;
    iphead->total_length = 0x0028;
    iphead->id = 0xabcd;
    iphead->flags_n_offset = 0x0000;
    iphead->time_to_live = 0x40;
    iphead->protocol = 0x06;
    iphead->checksum = 0x00;
    iphead->src_address = 0x0a0a0a02;

    tcphead->src_port = 0x3039;
    tcphead->sequence_num = 0x0050;
    tcphead->ack_num = 0x00000000;
    tcphead->offset_n_reserved = 0x50;
    tcphead->control_bits = 0x02;
    tcphead->window = 0x7110;
    tcphead->checksum = 0x00;
    tcphead->urgent_ptr = 0x0000;

    /* Setting destination ipv4 and port num */
    memcpy(&iphead->dst_address, &dst_address, sizeof(dst_address));
    memcpy(&tcphead->dst_port, &dst_port, sizeof(dst_port));
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

void hexDump(void *buffer, size_t length) {
    unsigned char* p = (unsigned char*) buffer;

    for (size_t i = 0; i < length; i++) {
        printf("%02X ", p[i]);

        // Print an extra space after 8 bytes
        if ((i + 1) % 8 == 0)
            printf(" ");

        // Print a new line after 16 bytes
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    // Print a final new line if the last line wasn't complete
    if (length % 16 != 0)
        printf("\n");
}
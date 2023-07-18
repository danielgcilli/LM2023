#include "TCP_Header.h"


void TCP_set_src_port(TCP_Header_t* this, uint16_t src_port) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->src_port = src_port;
}

void TCP_set_dst_port(TCP_Header_t* this, uint16_t dst_port) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->dst_port = dst_port;
}

void TCP_set_sequence_num(TCP_Header_t* this, uint32_t seq_num) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->sequence_num = seq_num;
}

void TCP_set_ack_num(TCP_Header_t* this, uint32_t ack_num) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->ack_num = ack_num;
}

void TCP_set_offset(TCP_Header_t* this, uint8_t offset) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    offset = offset << 4;
    this->offset_n_reserved = this->offset_n_reserved | offset;
}

void TCP_set_reserved(TCP_Header_t* this, uint8_t reserved) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint8_t mask = 0xF0;
    uint8_t masked_offset_n_reserved = this->offset_n_reserved & mask;
    this->offset_n_reserved = masked_offset_n_reserved | reserved;
}

void TCP_set_control_bits(TCP_Header_t* this, uint8_t flags) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->control_bits = flags;
}

void TCP_set_window(TCP_Header_t* this, uint16_t window) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->window = window;
}

void TCP_set_checksum(TCP_Header_t* this, uint16_t checksum) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->checksum = checksum;
}

void TCP_set_ugent_ptr(TCP_Header_t* this, uint16_t urgent_ptr) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->urgent_ptr = urgent_ptr;
}

void TCP_update_checksum(TCP_Header_t* this, IP_Header_t* IP_segment) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(EXIT_FAILURE);
    }
    if (IP_segment == NULL) {
        perror("IP Segment is NULL");
        exit(EXIT_FAILURE);
    }

    const uint16_t TCP_LENGTH = 20;
    uint32_t tcp_checksum = 0;

    // protocol
    tcp_checksum = ones_complement_add(tcp_checksum, IP_segment->protocol);

    // source address
    uint16_t src_address_lower = IP_segment->src_address & 0xFFFF;
    uint16_t src_address_upper = (IP_segment->src_address >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, src_address_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, src_address_upper);

    // destination address
    uint16_t dst_address_lower = IP_segment->dst_address & 0xFFFF;
    uint16_t dst_address_upper = IP_segment->dst_address >> 16;
    tcp_checksum = ones_complement_add(tcp_checksum, dst_address_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, dst_address_upper);

    // TCP Length
    tcp_checksum = ones_complement_add(tcp_checksum, TCP_LENGTH);

    // source port
    tcp_checksum = ones_complement_add(tcp_checksum, this->src_port);

    // destination port 
    tcp_checksum = ones_complement_add(tcp_checksum, this->dst_port);

    // sequence number
    uint16_t seq_lower = this->sequence_num & 0xFFFF;
    uint16_t seq_upper = (this->sequence_num >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, seq_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, seq_upper);

    // acknowledgement number
    uint16_t ack_lower = this->ack_num & 0xFFFF;
    uint16_t ack_upper = (this->ack_num >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, ack_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, ack_upper);

    // offset, reserved, and control bits
    tcp_checksum = ones_complement_add(tcp_checksum, ((uint16_t)this->offset_n_reserved << 8) | (uint16_t)this->control_bits);

    // window
    tcp_checksum = ones_complement_add(tcp_checksum, this->window);

    // urgent pointer 
    tcp_checksum = ones_complement_add(tcp_checksum, this->urgent_ptr);

    // set one's complement
    this->checksum = ~tcp_checksum;
}
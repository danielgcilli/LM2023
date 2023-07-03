#include "packets.h"


void IP_set_version(IP_Header_t* this, uint8_t version) {
    uint8_t mask = 0x0F;
    uint8_t masked_version_n_IHL = this->version_n_IHL & mask;
    uint8_t shifted_version = version << 4;
    this->version_n_IHL = masked_version_n_IHL | shifted_version;
}

void IP_set_IHL(IP_Header_t* this, uint8_t IHL) {
    uint8_t mask = 0xF0;
    uint8_t masked_version_n_IHL = this->version_n_IHL & mask;
    mask = 0x0F;
    uint8_t formatted_IHL = IHL & mask;
    this->version_n_IHL = masked_version_n_IHL | formatted_IHL;
}

void IP_set_type_of_service(IP_Header_t* this, uint8_t type_of_service) {
    this->type_of_service = type_of_service;
}

void IP_set_total_length(IP_Header_t* this, uint16_t total_length) {
    this->total_length = total_length;
}

void IP_set_id(IP_Header_t* this, uint16_t id) {
    this->id = id;
}

void IP_set_flags(IP_Header_t* this, uint8_t flags) {
    uint16_t mask = 0x1FFF;
    uint16_t masked_flags_n_offset = this->flags_n_offset & mask;
    uint16_t shifted_flags = flags << 13;
    this->flags_n_offset = masked_flags_n_offset | shifted_flags;
}

void IP_set_offset(IP_Header_t* this, uint16_t offset) {
    uint16_t mask = 0xE0FF;
    uint16_t masked_flags_n_offset = this->flags_n_offset & mask;
    mask = 0x1FFF;
    uint16_t formatted_offset = offset & mask;
    this->flags_n_offset = masked_flags_n_offset | formatted_offset;
}

void IP_set_time_to_live(IP_Header_t* this, uint8_t time_to_live) {
    this->time_to_live = time_to_live;
}

void IP_set_protocol(IP_Header_t* this, uint8_t protocol) {
    this->protocol = protocol;
}

void IP_set_checksum(IP_Header_t* this, uint16_t checksum) {
    this->checksum = checksum;
}

void IP_set_src_address(IP_Header_t* this, uint32_t src_address) {
    this->src_address = src_address;
}

void IP_set_dst_address(IP_Header_t* this, uint32_t dst_address) {
    this->dst_address = dst_address;
}

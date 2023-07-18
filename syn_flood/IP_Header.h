#ifndef IP_HEADER_H
#define IP_HEADER_H


#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>


/**
 * @brief IP Header segment of the TCP/IP packet
 * 
 */
typedef struct  IP_Header {
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
} __attribute__((__packed__)) IP_Header_t;


/**
 * @brief Set the version field
 * 
 * @param self Instance of the IP_Header_t struct
 * @param version The new version
 */
void IP_set_version(IP_Header_t* this, uint8_t version);

/**
 * @brief Set the IP Header Length
 * 
 * @param this Instance of the IP_Header_t struct
 * @param IHP the new IP Header Length
 */
void IP_set_IHL(IP_Header_t* this, uint8_t IHL);

void IP_set_type_of_service(IP_Header_t* this, uint8_t type_of_service);

void IP_set_total_length(IP_Header_t* this, uint16_t total_length);

void IP_set_id(IP_Header_t* this, uint16_t id);

void IP_set_flags(IP_Header_t* this, uint8_t flags);

void IP_set_offset(IP_Header_t* this, uint16_t offset);

void IP_set_time_to_live(IP_Header_t* this, uint8_t time_to_live);

void IP_set_protocol(IP_Header_t* this, uint8_t protocol);

void IP_set_checksum(IP_Header_t* this, uint16_t checksum); 

void IP_set_src_address(IP_Header_t* this, uint32_t src_address);

void IP_set_dst_address(IP_Header_t* this, uint32_t dst_address);

/**
 * @brief Updates checksum using current values in structure
 * 
 * @param this Instance of the IP_Header_t struct
 */
void IP_update_checksum(IP_Header_t* this);

/**
 * @brief Add two numbers using one's complement arithmetic 
 * 
 * @param a The first number to be added
 * @param b The second number to be added
 * @return uint16_t The one's complement sum of a and b
 */
uint16_t ones_complement_add(uint16_t a, uint16_t b);


#endif
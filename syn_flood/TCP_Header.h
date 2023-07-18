#ifndef TCP_HEADER_H
#define TCP_HEADER_H


#include "IP_Header.h"


#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>


/**
 * @brief TCP Header segment of the TCP/IP packet
 * 
 */
typedef struct TCP_Header {
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
} TCP_Header_t;


void TCP_set_src_port(TCP_Header_t* this, uint16_t src_port);

void TCP_set_dst_port(TCP_Header_t* this, uint16_t dst_port);

void TCP_set_sequence_num(TCP_Header_t* this, uint32_t seq_num);

void TCP_set_ack_num(TCP_Header_t* this, uint32_t ack_num);

void TCP_set_offset(TCP_Header_t* this, uint8_t offset);

void TCP_set_reserved(TCP_Header_t* this, uint8_t reserved);

void TCP_set_control_bits(TCP_Header_t* this, uint8_t flags);

void TCP_set_window(TCP_Header_t* this, uint16_t window);

void TCP_set_checksum(TCP_Header_t* this, uint16_t checksum);

void TCP_set_ugent_ptr(TCP_Header_t* this, uint16_t urgent_ptr);

 /**
  * @brief Calculates and inserts checksum into TCP segment
  * 
  * @param this Pointer to the instance of the TCP_Header struct
  * @param IP_segment Pointer to the instance of the IP_Header struct
  */
void TCP_update_checksum(TCP_Header_t* this, IP_Header_t* IP_segment);


#endif
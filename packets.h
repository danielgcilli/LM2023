#ifndef PACKETS_H
#define PACKETS_H


/* General Libraries*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h> 
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

/* Libraries for Sockets */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>


#define IO_LIMIT 3

typedef unsigned char byte;


/* STRUCTURES */

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
} __attribute__((__packed__)) TCP_Header_t;


/* PROTOTYPES */


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

void randomize_src(IP_Header_t* this, uint32_t random_num);

/**
 * @brief Serialize the IP_Header_t struct into a buffer with network byte ordering
 * 
 * @param ip_header Pointer to the instance of the IP_Header_t struct to be serialized
 * @return byte* Pointer to the beginning of the serialized buffer
 */
byte *serialize_ip_header(IP_Header_t *ip_header);

/**
 * @brief Serialize the TCP_Header_t struct into a buffer with network byte ordering
 * 
 * @param tcp_header Pointer to the instance of the TCP_Header_t struct to be serialized
 * @return byte* Pointer to the beginning of the buffer with serialized TCP_Header_t
 */
byte *serialize_tcp_header(TCP_Header_t *tcp_header);

/**
 * @brief Calculates and inserts checksum into serialized IP_Header_t
 * 
 * @param ip_stream Pointer to the beginning of the serialized IP_Header_t
 */
void update_ip_checksum(void* ip_stream);

/**
 * @brief Calculates and inserts checksum into serialized TCP_Header_t
 * 
 * @param tcp_stream Pointer to the beginning of the serialized TCP_Header_t
 */
void update_tcp_checksum(void* tcp_stream);

/**
 * @brief Updates the checksums of a serialized TCP/IP packet
 * 
 * @param packet_stream Pointer to the beginning of the serialized packet
 */
void update_checksums(void* packet_stream);

/**
 * @brief combines the serialized streams of the IP Header and TCP Header
 * 
 * @param ip_stream Pointer to the beginning of the serialized IP_Header_t
 * @param tcp_stream Pointer to the beginning of the serialized TCP_Header_t
 * @return byte* Pointer to the beginning of the serialized packet
 */
byte *form_packet(byte *ip_stream, byte *tcp_stream);

/**
 * @brief Populates IP and TCP headers with SYN fields
 * 
 * @param iphead Pointer to the instance of the IP_Header_t struct to be populated
 * @param tcphead Pointer to the instance of the TCP_Header_t struct to be populated
 * @param dst_address The destination ip address of the packet
 * @param dst_port The destination port of the packet
 */
void fill_SYN(IP_Header_t *iphead, TCP_Header_t *tcphead, uint32_t dst_address, uint16_t dst_port);

/**
 * @brief Dumps the binary of the specified stream/buffer
 * 
 * @param stream The stream/buffer to be read
 * @param numbytes The number of bytes to be read
 * @param endianess The endianness of the architecture
 */
void bin_dump(byte *stream, int numbytes, int endianess);

/**
 * @brief Dumps the hex of the specified stream/buffer
 * 
 * @param buffer The stream/buffer to be read
 * @param length The number of bytes to be read
 */
void hexDump(void *buffer, size_t length);

#endif
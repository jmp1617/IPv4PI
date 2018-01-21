//--------------------------------
//
// Set of functions and routines 
// for packet inpection/disection
//
// spec
//
//-------------------------------

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//Macros

#define MIN_IPV4 20 // just header
#define MAX_IPV4 65535

//-----------------------------------------------------
// Data Structures
//-----------------------------------------------------
//
// struct to hold the packet metadata
//
// if the ethernet header is present then the respecive flag will be one.
// if the ethernet checksum is also present then the respecive flag will
// be one and the checksum can be evaluated and recomputed.
//
//------------------------------
struct packet_meta_s{
    FILE* packet;
    //flags
    unsigned ethernet_flag: 1; // whether or not ethernet header is present or stripped
    unsigned fcs_active: 1; // whether or not ethernet checksum included
    unsigned pre_del: 1; // whether or not the preamble and frame delimiter is present
    unsigned llc: 1; // if 802.1Q tag is present
    //counts
    unsigned int byte_count; // number of bytes in the packet
    unsigned int payload_size;
};

typedef struct packet_meta_s* Packet_Meta;

//------------------------------
//
// struct to hold the ipv4 header info
//
//------------------------------
struct ipv4_header_s{
    //-------------------------- 0
    unsigned version: 4; // 4 for ipv4
    unsigned ihl: 4; // Internet Header Length
    unsigned dscp: 6; // Differentiated Services Code Point
    unsigned ecn: 2; // Explicit Congestion Notification
    //-------------------------- 16
    uint16_t total_length;
    //-------------------------- 32
    uint16_t identification;
    //-------------------------- 48
    unsigned flags: 3;
    unsigned fragment_offset: 13; 
    //-------------------------- 64
    uint8_t ttl; // time to live
    uint8_t protocol;
    //-------------------------- 80
    uint16_t header_checksum;
    //-------------------------- 96
    uint32_t source_ip;
    uint32_t destination_ip;
    //-------------------------- 128
};

typedef struct ipv4_header_s* IPv4_Header;

//------------------------------
//
// struct to hold ethernet II header info
// 
// does not include preamble or frame delimeter
//
//------------------------------
struct ethernet_header_s{
    //-------------------------- 0
    uint8_t* destination;
    //-------------------------- 48
    uint8_t* source;
    //-------------------------- 96
    uint32_t llc; // optional - specified in metadata
    //-------------------------- 128
    uint16_t ethertype;
    //-------------------------- 144
    // payload
    //-------------------------- 46 - 1500 octets
    uint32_t fcs;
    //-------------------------- +32
};

typedef struct ethernet_header_s* Ethernet_Header;

//-----------------------------------------------------
// Initialization - memory allocations
//-----------------------------------------------------

Packet_Meta create_packet_meta();
IPv4_Header create_ip_header();
Ethernet_Header create_eII_header();

//-----------------------------------------------------
// Load into memory
//-----------------------------------------------------

//------------------------------
//
// read in the ipv4 header from a file pointer
//
// :pm -> packet metadate structure
// :ih -> ipv4 header structure
// 
// returns success
//------------------------------
int load_ip_header_f(Packet_Meta pm, IPv4_Header ih);

//------------------------------
//
// read in the ethernet header from a file pointer
// 
// :pm -> packet metadata structure
// :eh -> ethernet 2 header structure
//
// return success
//------------------------------
int load_eII_header_f(Packet_Meta pm, Ethernet_Header eh);

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
#include <arpa/inet.h>

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
// if they byte count or payload size are 0 they have not yet been set
//
//------------------------------
struct packet_meta_s{
    FILE* packet;
    //flags
    unsigned ethernet_flag: 1; // whether or not ethernet header is present or stripped
    unsigned fcs_active: 1; // whether or not ethernet checksum included
    unsigned pre_del: 1; // whether or not the preamble and frame delimiter is present
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
    uint8_t* source_ip;
    uint8_t* destination_ip;
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
    uint16_t ethertype;
    //-------------------------- 112
    // payload
    //-------------------------- 46 - 1500 octets
    uint32_t fcs;
    //-------------------------- +32
};

typedef struct ethernet_header_s* Ethernet_Header;

//------------------------------
//
// struct to hold packet data
//
//------------------------------
struct packet_s{
    Ethernet_Header eh;
    IPv4_Header ih;
    uint8_t* payload;
};

typedef struct packet_s* Packet;

//-----------------------------------------------------
// Initialization - memory allocations
//-----------------------------------------------------

Packet_Meta create_packet_meta();
IPv4_Header create_ip_header();
Ethernet_Header create_eII_header();
Packet create_packet();

//--------------( k λ )/|---------------------------------------
// set the initial packet metadata
// 
// pm-> packet meta data structure: Packet_Meta
// fn-> file name: string
// eth-> use ethernet header: flag (int 0 or 1)
// fcs-> frame check sum: flag (int 0 or 1)
// pre-> preamble and sync present: flag (int 0 or 1)
// bc-> byte count: int
// ps-> payload size: int
//-----------------------------------------------------
int init_md_f(Packet_Meta pm, char* fn, int eth, int fcs, int pre, unsigned int bc, unsigned int ps);

//-----------------------------------------------------
// Auxilary
//-----------------------------------------------------

void print_usage(char* usage);

//-----------------------------------------------------
// Load into memory
//-----------------------------------------------------

//------------------------------
//
// read in the ipv4 header from a file pointer
//
// :pm -> packet metadata structure
// :ih -> ipv4 header structure
// 
// returns success
//------------------------------
int load_ip_header_f(Packet_Meta pm, IPv4_Header ih);

//------------------------------
//
// read in the ethernet header from a file pointer
// does not read in crc
//
// :pm -> packet metadata structure
// :eh -> ethernet 2 header structure
//
// return success
//------------------------------
int load_eII_header_f(Packet_Meta pm, Ethernet_Header eh);

//-----------------------------------------------------
// display functions - ethernet
//-----------------------------------------------------
void de_destination(Packet p);
void de_source(Packet p);
void de_ethtype(Packet p);
void de_fcs(Packet p);

//-----------------------------------------------------
// display functions - ipv4
//-----------------------------------------------------
void di_version(Packet p);
void di_headerlen(Packet p);
void di_dscp(Packet p);
void di_totlen(Packet p);
void di_ident(Packet p);
void di_flags(Packet p);
void di_fragoff(Packet p);
void di_ttl(Packet p);
void di_protocol(Packet p);
void di_headcheck(Packet p);
void di_source(Packet p);
void di_dest(Packet p);

//-----------------------------------------------------
// payload
//-----------------------------------------------------

//-----------------------------------------------------
//
// read in the payload bytes
//
// :p -> packet structure
//
// return sucess
//-----------------------------------------------------
int load_payload_f(Packet p, Packet_Meta pm);

//------------------------------
//
// display the packet bytewise and indent on bi word (64 bit)
// hexadecimal
// 
// :pm -> packet metadata struct
// :p -> packet struct
//------------------------------
void display_payload_x(Packet p, Packet_Meta pm);

//------------------------------
//
// display the packet in ascii chars and indent on bi word
// 
// :no_a_c -> char to print if not in extended ascii encoding
//      or non visual
// :pm -> packet metadata struct
// :p -> packet struct
//
//------------------------------
void display_payload_c(Packet p, Packet_Meta pm, char no_a_c);

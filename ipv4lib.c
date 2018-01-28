//---https://www.google.com/-----------------------------
//
// Set of functions and routines 
// for packet inpection/disection
//
// implimentation
//
//-------------------------------

#include "ipv4lib.h"

//-----------------------------------------------------
// Initialization
//-----------------------------------------------------

Packet_Meta create_packet_meta(){
    Packet_Meta pm = (Packet_Meta)calloc(1, sizeof(struct packet_meta_s));
    if(pm)
        return pm;
    else{
        fprintf(stderr, "Calloc failed at creating Packet Metadata\n");
        return 0;
    }
}

IPv4_Header create_ip_header(){
    IPv4_Header ih = (IPv4_Header)calloc(1, sizeof(struct ipv4_header_s));
    if(ih)
        return ih;
    else{
        fprintf(stderr, "Calloc failed at creating IP header\n");
        return 0;
    }
}

Ethernet_Header create_eII_header(){
    Ethernet_Header eh = (Ethernet_Header)calloc(1, sizeof(struct ethernet_header_s));
    if(eh)
        return eh;
    else{
        fprintf(stderr, "Calloc failed at creating Eth header\n");
        return 0;
    }
}

Packet create_packet(){
    Packet p = (Packet)calloc(1, sizeof(struct packet_s));
    if(p){
        p->eh = create_eII_header();
        p->ih = create_ip_header();
        p->payload = 0;
        return p;
    }
    else{
        fprintf(stderr, "Calloc failed at creating Packet\n");
        return 0;
    }
}

int init_md_f(Packet_Meta pm, char* fn, int eth, int fcs, int pre, unsigned int bc, unsigned int ps){
    if(pm){
        pm->packet = fopen(fn, "wr");
        if(!pm->packet){
            fprintf(stderr,"Could not open file\n");
            return 0;
        }
        pm->ethernet_flag|=eth;
        pm->fcs_active|=fcs;
        pm->pre_del|=pre;
        pm->byte_count = bc;
        pm->payload_size = ps;
        return 1;
    }
    fprintf(stderr,"Packet meta struct is Null\n");
    return 0;
}

//-----------------------------------------------------
// Auxilary
//-----------------------------------------------------

void print_usage(char* usage){
    printf("%s", usage);
}

//-----------------------------------------------------
// Load into Memory
//-----------------------------------------------------

int load_ip_header_f(Packet_Meta pm, IPv4_Header ih){
    //read in first byte containing both version and IHL
    if(!pm || !ih){
        fprintf(stderr,"Either Packet_Meta or IPv4_Header is null\n");
        return 0;
    }
    uint8_t temp;
    uint16_t temp16;
    fread(&temp, 1, 1, pm->packet);
    ih->version = 0xF & temp; 
    temp <<= 4;
    ih->ihl = 0xF & temp;
    //read in byte containing dscp and ecn
    fread(&temp, 1, 1, pm->packet);
    ih->dscp = 0x3F & temp;
    temp <<= 6;
    ih->ecn = 0x3 & temp;
    //read in total length
    fread(&(ih->total_length), 2, 1, pm->packet);
    //identification
    fread(&(ih->identification), 2, 1, pm->packet);
    //flags and fragment offset
    fread(&temp16, 2, 1, pm->packet);
    ih->flags = 0x7 & temp16;
    temp16 <<= 3;
    ih->fragment_offset = 0x1FFF & temp16;
    //ttl byte
    fread(&(ih->ttl), 1, 1, pm->packet);
    //protocol
    fread(&(ih->protocol), 1, 1, pm->packet);
    //checksum
    fread(&(ih->header_checksum), 2, 1, pm->packet);
    //source ip
    fread(&(ih->source_ip), 4, 1, pm->packet);
    //dest ip
    fread(&(ih->destination_ip), 4, 1, pm->packet);
    return 1;
}

int load_eII_header_f(Packet_Meta pm, Ethernet_Header eh){
    if(!pm || !eh){
        fprintf(stderr,"Either Packet_Meta or Eth_Header is null\n");
        return 0;
    }
    //read in the 6 byte destination mac
    eh->destination = (uint8_t*)calloc(6,sizeof(uint8_t));
    fread(eh->destination, 1, 6, pm->packet);
    //read in the source mac
    eh->source = (uint8_t*)calloc(6,sizeof(uint8_t));
    fread(eh->source, 1, 6, pm->packet);
    //read in the ethertype
    fread(&(eh->ethertype), 2, 1, pm->packet);
    return 1;
}

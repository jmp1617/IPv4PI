//--------------------------------
//
// Set of functions and routines 
// for packet inpection/disection
//
// implimentation
//
//-------------------------------

#include <ipv4lib.h>

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
    }
}

//-----------------------------------------------------
// Load into Memory
//-----------------------------------------------------

int load_ip_header_f(Packet_Meta pm, IPv4_Header ih){
    //read in first byte containing both version and IHL
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
}

int load_eII_header_f(Packet_Meta pm, Ethernet_Header eh){
    //read in the 6 byte destination mac
    eh->destination = (uint8_t*)calloc(6,sizeof(uint8_t));
    fread(eh->destination, 1, 6, pm->packet);
    //read in the source mac
    eh->source = (uint8_t*)calloc(6,sizeof(uint8_t));
    fread(eh->source, 1, 6, pm->packet);
    //read in the ethertype
    fread(&(eh->ethertype), 2, 1, pm->packet);
}

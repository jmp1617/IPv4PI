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

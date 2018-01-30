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
    if(eh){
        eh->destination = calloc(6, sizeof(uint8_t));
        eh->source = calloc(6, sizeof(uint8_t));
        return eh;
    }
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
        pm->packet = fopen(fn, "r");
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
    ih->ihl = 0xF & temp; 
    temp >>= 4;
    ih->version = 0xF & temp;
    //read in byte containing dscp and ecn
    fread(&temp, 1, 1, pm->packet);
    ih->dscp = 0x3F & temp;
    temp >>= 6;
    ih->ecn = 0x3 & temp;
    //read in total length
    fread(&(ih->total_length), 2, 1, pm->packet);
    //identification
    fread(&(ih->identification), 2, 1, pm->packet);
    //flags and fragment offset
    fread(&temp16, 2, 1, pm->packet);
    temp16 = ntohs(temp16);
    ih->fragment_offset = 0x1FFF & temp16;
    temp16 >>= 13;   
    ih->flags = 0x7 & temp16;
    //ttl byte
    fread(&(ih->ttl), 1, 1, pm->packet);
    //protocol
    fread(&(ih->protocol), 1, 1, pm->packet);
    //checksum
    fread(&(ih->header_checksum), 2, 1, pm->packet);
    //source ip
    ih->source_ip = (uint8_t*)calloc(4,sizeof(uint8_t));
    if(!ih->source_ip){
        fprintf(stderr,"Calloc failed at allocating source ip\n");
        return 0;
    }
    fread(ih->source_ip, 1, 4, pm->packet);
    //dest ip
    ih->destination_ip = (uint8_t*)calloc(4,sizeof(uint8_t));
    if(!ih->destination_ip){
        fprintf(stderr,"Calloc failed at allocating destination ip\n");
        return 0;
    }
    fread(ih->destination_ip, 1, 4, pm->packet);
    //calculate byte count and payload size
    pm->payload_size = ntohs(ih->total_length) - ((ih->ihl*32)/8);
    //calculate total length
    pm->byte_count = ntohs(ih->total_length);
    if(pm->ethernet_flag)
        pm->byte_count += 14;
    if(pm->fcs_active)
        pm->byte_count += 4;
    if(pm->pre_del)
        pm->byte_count += 8;
    return 1;
}

int load_eII_header_f(Packet_Meta pm, Ethernet_Header eh){
    if(!pm || !eh){
        fprintf(stderr,"Either Packet_Meta or Eth_Header is null\n");
        return 0;
    }
    //read in the 6 byte destination mac
    eh->destination = (uint8_t*)calloc(6,sizeof(uint8_t));
    if(!eh->destination){
        fprintf(stderr,"Calloc failed at allocating destination mac\n");
        return 0;
    }
    fread(eh->destination, 1, 6, pm->packet);
    //read in the source mac
    eh->source = (uint8_t*)calloc(6,sizeof(uint8_t));
    if(!eh->source){
        fprintf(stderr,"Calloc failed at allocating source mac\n");
        return 0;
    }
    fread(eh->source, 1, 6, pm->packet);
    //read in the ethertype
    fread(&(eh->ethertype), 2, 1, pm->packet);
    return 1;
}

//-----------------------------------------------------
// display functions - ethernet
//-----------------------------------------------------
void de_destination(Packet p){
    for(int byte = 0; byte<6; byte++){
        if(byte!=5)
            printf("%02x:",*(p->eh->destination+byte));
        else
            printf("%02x",*(p->eh->destination+byte));
    }
}

void de_source(Packet p){
    for(int byte = 0; byte<6; byte++){
        if(byte!=5)
            printf("%02x:",*(p->eh->source+byte));
        else
            printf("%02x",*(p->eh->source+byte));
    }
}

void de_ethtype(Packet p){
    printf("0x%04x", ntohs(p->eh->ethertype));
}

void de_fcs(Packet p){
    if(p->eh->fcs)
        printf("0x%08x", ntohl(p->eh->fcs));
    else
        printf("fcs not active");
}

//-----------------------------------------------------
// display functions - ethernet
//-----------------------------------------------------
void di_version(Packet p){
    printf("%d",p->ih->version);
}

void di_headerlen(Packet p){
    printf("%d (%d bytes)",p->ih->ihl,((p->ih->ihl)*32)/8);
}

void di_dscp(Packet p){
    uint8_t dsc = 0; dsc = p->ih->dscp & 0x3f;
    uint8_t temp = p->ih->dscp; temp >>= 6;
    uint8_t ecn = 0; ecn = temp & 0x3;
    printf("DSC: %d ECN: %d", dsc, ecn);
}

void di_totlen(Packet p){
    printf("%d", ntohs(p->ih->total_length));
}

void di_ident(Packet p){
    printf("0x%04x", ntohs(p->ih->identification));
}

void di_flags(Packet p){
    printf("(0x%02x) Reserved: %d, Don't fragment: %d, More fragments: %d", p->ih->flags, p->ih->flags&0x4, p->ih->flags&0x2, p->ih->flags&0x1);
}

void di_fragoff(Packet p){
    printf("%d", p->ih->fragment_offset);
}

void di_ttl(Packet p){
    printf("%d", p->ih->ttl);
}

void di_protocol(Packet p){
    printf("%d", p->ih->protocol);
}

void di_headcheck(Packet p){
    printf("0x%04x", ntohs(p->ih->header_checksum));
}

void di_source(Packet p){
    for(int byte = 0; byte<4; byte++){
        if(byte<3)
            printf("%d:", p->ih->source_ip[byte]);
        else
            printf("%d", p->ih->source_ip[byte]);
    }
}

void di_dest(Packet p){
    for(int byte = 0; byte<4; byte++){
        if(byte<3)
            printf("%d:", p->ih->destination_ip[byte]);
        else
            printf("%d", p->ih->destination_ip[byte]);
    }
}

//-----------------------------------------------------
// payload
//-----------------------------------------------------

int load_payload_f(Packet p, Packet_Meta pm){
    if(!p->ih)
        fprintf(stderr,"Warning; ip header is unloaded, continuing anyway.\n");
    if(!p || !pm){
        fprintf(stderr,"Error, packet or packet meta is NULL\n");
        return 0;
    }
    p->payload = (uint8_t*)calloc(pm->payload_size,sizeof(uint8_t));
    if(!p->payload){
        fprintf(stderr,"Calloc failed at allocating payload\n");
        return 0;
    }
    fread(p->payload, 1, pm->payload_size, pm->packet);
    return 1;
}

void display_payload_x(Packet p, Packet_Meta pm){
    unsigned align = 0x0;
    printf("%04x:  ",align);align+=0x8;
    for(unsigned byte = 1; byte<pm->payload_size+1; byte++){
        if(byte%8==0){
            printf("%02x\n",p->payload[byte-1]);
            if(byte!=pm->payload_size){
                printf("%04x:  ",align);align+=0x8;
            }
        }
        else
            printf("%02x ",p->payload[byte-1]);
    }
}

void display_payload_c(Packet p, Packet_Meta pm, char no_a_c){
    unsigned align = 0x0;
    unsigned ch = 0;
    printf("%04x:  ",align);align+=0x8;
    for(unsigned byte = 1; byte<pm->payload_size+1; byte++){
        ch = p->payload[byte-1];
        //non printables
        if(p->payload[byte-1] < 32 || p->payload[byte-1] == 127)
            ch = no_a_c;
        if(byte%8==0){
            printf(" %c\n", ch);
            if(byte!=pm->payload_size){
                printf("%04x:  ",align);align+=0x8;
            }
        }
        else
            printf(" %c ", ch);
    }
}

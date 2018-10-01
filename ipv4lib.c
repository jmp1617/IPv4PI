//--------------------------------
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
    if(ih){
        ih->source_ip = (uint8_t*)calloc(4,sizeof(uint8_t));
        ih->destination_ip = (uint8_t*)calloc(4,sizeof(uint8_t));
        return ih;
    }
    else{
        fprintf(stderr, "Calloc failed at creating IP header\n");
        return 0;
    }
}

Ethernet_Header create_eII_header(){
    Ethernet_Header eh = \
        (Ethernet_Header)calloc(1, sizeof(struct ethernet_header_s));
    if(eh){
        eh->destination = (uint8_t*)calloc(6, sizeof(uint8_t));
        eh->source = (uint8_t*)calloc(6, sizeof(uint8_t));
        return eh;
    }
    else{
        fprintf(stderr, "Calloc failed at creating Eth header\n");
        return 0;
    }
}

TCP_Header create_tcp_header(){
    TCP_Header th = (TCP_Header)calloc(1, sizeof(struct tcp_header_s));
    if(th)
        return th;
    else{
        fprintf(stderr, "Calloc failed at creating tcp header\n");
        return 0;
    }
}

UDP_Header create_udp_header(){
    UDP_Header uh = (UDP_Header)calloc(1, sizeof(struct udp_header_s));
    if(uh)
        return uh;
    else{
        fprintf(stderr, "Calloc failed at creating udp header\n");
        return 0;
    }
}

Packet create_packet(){
    Packet p = (Packet)calloc(1, sizeof(struct packet_s));
    if(p){
        p->eh = create_eII_header();
        p->ih = create_ip_header();
        p->th = NULL; // will be created based on the ipv4 protocol
        p->uh = NULL;
        p->payload = 0;
        return p;
    }
    else{
        fprintf(stderr, "Calloc failed at creating Packet\n");
        return 0;
    }
}

int init_md_f(Packet_Meta pm, char* fn, int eth, int fcs, int pre, \
        unsigned int bc, unsigned int ps){
    if(pm){
        if(fn[0]=='0'){
            pm->packet = stdin;
        }
        else{
            pm->packet = fopen(fn, "r");
            if(!pm->packet){
                fprintf(stderr,"Could not open file\n");
                return 0;
            }
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

int init_md_s(Packet_Meta pm, int eth, int fcs, int pre, \
        unsigned int bc, unsigned int ps){
    if(pm){
        //create the socket
        pm->socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
        if(pm->socket<0){
            fprintf(stderr,"Socket Error\nDid you run as root?\n");
            return 0;
        }
        pm->packet_buffer = (uint8_t*)malloc(65536);
        pm->pbp = 0;
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
// Packet Emission
//-----------------------------------------------------
int write_to_packet_buffer(Packet_Meta pm, Packet p){
    if(!pm || !p){
        fprintf(stderr,"Packet Meta or Packet is null in write_to_packet_buffer");
        return 0;
    }
    memset(pm->packet_buffer,0,MAX_IPV4);
    pm->pbp = 0;
    if(p->eh){
        Ethernet_Header eh = p->eh;
        memcpy(pm->packet_buffer+pm->pbp, eh->destination, 6);
        pm->pbp+=6;
        memcpy(pm->packet_buffer+pm->pbp, eh->source, 6);
        pm->pbp+=6;
        memcpy(pm->packet_buffer+pm->pbp,&(eh->ethertype), 2);
        pm->pbp+=2;
    }
    if(p->ih){
        IPv4_Header ih = p->ih;
        uint8_t temp;
        uint16_t temp16;
        temp = ih->version;
        temp <<= 4;
        temp |= ih->ihl;
        memcpy(pm->packet_buffer+pm->pbp,&temp,1);
        pm->pbp++;
        temp = ih->dscp;
        temp <<= 6;
        temp |= ih->ecn;
        memcpy(pm->packet_buffer+pm->pbp,&temp,1);
        pm->pbp++;
        memcpy(pm->packet_buffer+pm->pbp,&(ih->total_length),2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&(ih->identification),2);
        pm->pbp+=2;
        temp16 = ih->fragment_offset;
        temp16 <<= 3;
        temp16 |= ih->flags;
        temp16 = htons(temp16);
        memcpy(pm->packet_buffer+pm->pbp,&temp16,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&(ih->ttl),1);
        pm->pbp++;
        memcpy(pm->packet_buffer+pm->pbp,&(ih->protocol),1);
        pm->pbp++;
        memcpy(pm->packet_buffer+pm->pbp,&(ih->header_checksum),2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,ih->source_ip,4);
        pm->pbp+=4;
        memcpy(pm->packet_buffer+pm->pbp,ih->destination_ip,4);
        pm->pbp+=4;
    }
    if(p->th){
        TCP_Header th = p->th;
        uint8_t temp;
        memcpy(pm->packet_buffer+pm->pbp,&th->source_port,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&th->destin_port,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&th->seq_num,4);
        pm->pbp+=4;
        memcpy(pm->packet_buffer+pm->pbp,&th->ack_number,4);
        pm->pbp+=4;
        temp = th->data_offset;
        temp <<= 5;
        temp |= th->reserved;
        temp <<= 2;
        temp |= th->ns;
        memcpy(pm->packet_buffer+pm->pbp,&temp,1);
        pm->pbp++;
        temp = th->cwr;temp<<=1;
        temp |= th->ece;temp<<=1;
        temp |= th->urg;temp<<=1;
        temp |= th->ack;temp<<=1;
        temp |= th->psh;temp<<=1;
        temp |= th->rst;temp<<=1;
        temp |= th->syn;temp<<=1;
        temp |= th->fin;temp<<=1;
        memcpy(pm->packet_buffer+pm->pbp,&temp,1);
        pm->pbp++;
        memcpy(pm->packet_buffer+pm->pbp,&th->win_size,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&th->check,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&th->urgent_point,2);
        pm->pbp+=2;
        unsigned o_size = ((th->data_offset * 32) / 8) - 20;
        th->options = (uint8_t*)calloc(o_size, sizeof(uint8_t));
        memcpy(pm->packet_buffer+pm->pbp,th->options,o_size);
        pm->pbp+=o_size;
    }
    if(p->uh){
        UDP_Header uh = p->uh;
        memcpy(pm->packet_buffer+pm->pbp,&uh->source_port,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&uh->destin_port,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&uh->length,2);
        pm->pbp+=2;
        memcpy(pm->packet_buffer+pm->pbp,&uh->check,2);
        pm->pbp+=2;
    }
    if(p->payload > 0){
       memcpy(pm->packet_buffer+pm->pbp, p->payload, pm->payload_size);
       pm->pbp+=pm->payload_size;
    }
    return 1;
}

int emmit_packet(Packet_Meta pm, int port){

}

//-----------------------------------------------------
// Auxilary
//-----------------------------------------------------

void print_usage(char* usage){
    printf("%s", usage);
}

void byte_replace(uint8_t* bytes, uint8_t* nbytes, int ibc, int nbc, int off){
    if(off+nbc > ibc)
        fprintf(stderr,"Offset to large\n");
    else{
        for(int byte = 0; byte < nbc; byte++){
            bytes[byte+off] = nbytes[byte];
        }
    }
}

//-----------------------------------------------------
// Socket Aux
//-----------------------------------------------------
int socket_to_buffer(Packet_Meta pm){
    memset(pm->packet_buffer,0,MAX_IPV4 + 1);
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    int reclen = recvfrom(pm->socket,pm->packet_buffer,MAX_IPV4 + 1,0,&saddr,(socklen_t *)&saddr_len);
    if(reclen<0){
        fprintf(stderr, "Error reading from Socket\n");
        return 0;
    }
    pm->byte_count = reclen;
    return 1;
}

void reset_pbp(Packet_Meta pm){
    pm->pbp = 0;
}

int get_pbp(Packet_Meta pm){
    return pm->pbp;
}

//-----------------------------------------------------
// Load into Memory
//-----------------------------------------------------

int load_ip_header_f(Packet_Meta pm, IPv4_Header ih){
    //read in first byte containing both version and IHL
    if(!pm || !ih){
        fprintf(stderr,"Either Packet_Meta or IPv4_Header is \
        null at loading ip header\n");
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
    ih->ecn = 0x3 & temp;
    temp >>= 2;
    ih->dscp = 0x3F & temp;
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
    fread(ih->source_ip, 1, 4, pm->packet);
    //dest ip
    fread(ih->destination_ip, 1, 4, pm->packet);
    //calculate total length
    pm->byte_count = ntohs(ih->total_length);
    if(pm->byte_count>MAX_IPV4){ // Invalid IPv4 packet
        fprintf(stderr, "WARNING: Byte count greater than the max. Truncating");
        pm->byte_count = MAX_IPV4;
        ih->total_length = htons(pm->byte_count); // reset total_length
    }
    if(pm->byte_count<MIN_IPV4){
        fprintf(stderr, "WARNING: Byte count less than min.");
    }
    //calculate byte count and payload size
    pm->payload_size = ntohs(ih->total_length) - ((ih->ihl*32)/8);
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
        fprintf(stderr,"Either Packet_Meta or Eth_Header is \
        null at loading eth header\n");
        return 0;
    }
    //read in the 6 byte destination mac
    fread(eh->destination, 1, 6, pm->packet);
    //read in the source mac
    fread(eh->source, 1, 6, pm->packet);
    //read in the ethertype
    fread(&(eh->ethertype), 2, 1, pm->packet);
    return 1;
}

int load_tcp_header_f(Packet_Meta pm, TCP_Header th){
    if(!pm || !th){
        fprintf(stderr, "Either Packet_Meta or TCP_Header is \
        null at loading tcp header\n");
        return 0;
    }
    //read in source port
    fread(&th->source_port, 2, 1, pm->packet);
    //read in dest port
    fread(&th->destin_port, 2, 1, pm->packet);
    //read in sequence number
    fread(&th->seq_num, 4, 1, pm->packet);
    //read in the ack number
    fread(&th->ack_number, 4, 1, pm->packet);
    uint8_t temp;
    fread(&temp, 1, 1, pm->packet);
    //ns flag
    th->ns = 0x1 & temp;
    temp >>= 1;
    //reserved should be zero
    th->reserved = 0x7 & temp;
    temp >>= 3;
    //data_offset
    th->data_offset = 0xF & temp;
    fread(&temp, 1, 1, pm->packet);
    //the rest of the flags
    th->fin = 0x1 & temp;temp>>=1;
    th->syn = 0x1 & temp;temp>>=1;
    th->rst = 0x1 & temp;temp>>=1;
    th->psh = 0x1 & temp;temp>>=1;
    th->ack = 0x1 & temp;temp>>=1;
    th->urg = 0x1 & temp;temp>>=1;
    th->ece = 0x1 & temp;temp>>=1;
    th->cwr = 0x1 & temp;temp>>=1;
    //win_size
    fread(&th->win_size, 2, 1, pm->packet);
    //checksum
    fread(&th->check, 2, 1, pm->packet);
    //urgent pointer
    fread(&th->urgent_point, 2, 1, pm->packet);
    //size of options
    unsigned o_size = ((th->data_offset * 32) / 8) - 20;
    th->options = (uint8_t*)calloc(o_size, sizeof(uint8_t));
    fread(th->options, 1, o_size, pm->packet);

    //recalculate payload size
    pm->payload_size = pm->payload_size - ((th->data_offset * 32) / 8);

    return 1;
}

int load_udp_header_f(Packet_Meta pm, UDP_Header uh){
    if(!pm || !uh){
        fprintf(stderr, "Either Packet_Meta or UDP_Header is \
        null at loading udp header\n");
        return 0;
    }
    fread(&uh->source_port, 2, 1, pm->packet);
    fread(&uh->destin_port, 2, 1, pm->packet);
    fread(&uh->length, 2, 1, pm->packet);
    fread(&uh->check, 2, 1, pm->packet);

    //recalculate payload size
    pm->payload_size = ntohs(uh->length) - 8;

    return 1;
}

//-----------------------------------------------------
// load into memory - socket
//-----------------------------------------------------

int load_eII_header_s(Packet_Meta pm, Ethernet_Header eh){
    if(!pm || !eh){
        fprintf(stderr, "Ether Packet_Meta or Ethernet_Header is \
                null at loading tcp header\n");
        return 0;
    }
    //copy in the 6 byte dest mac
    memcpy(eh->destination, pm->packet_buffer+pm->pbp, 6);
    pm->pbp+=6;
    //copy in the source
    memcpy(eh->source, pm->packet_buffer+pm->pbp, 6);
    pm->pbp+=6;
    //ethertype
    memcpy(&(eh->ethertype),pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    return 1;
}

int load_ip_header_s(Packet_Meta pm, IPv4_Header ih){
    if(!pm || !ih){
        fprintf(stderr, "Ether Packet_Meta or IPv4_Header is \
                null at loading tcp header\n");
        return 0;
    }
    uint8_t temp;
    uint16_t temp16;
    //read in first byte containing both version and IHL
    memcpy(&temp,pm->packet_buffer+pm->pbp,1);
    pm->pbp++;
    ih->ihl = 0xF & temp;
    temp >>= 4;
    ih->version = 0xF & temp;
    //read in byte containing dscp and ecn
    memcpy(&temp,pm->packet_buffer+pm->pbp,1);
    pm->pbp++;
    ih->ecn = 0x3 & temp;
    temp >>= 2;
    ih->dscp = 0x3F & temp;
    //read in total length
    memcpy(&(ih->total_length),pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    //identification
    memcpy(&(ih->identification),pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    //flags and fragment offset
    memcpy(&temp16,pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    temp16 = ntohs(temp16);
    ih->fragment_offset = 0x1FFF & temp16;
    temp16 >>= 13;
    ih->flags = 0x7 & temp16;
    //ttl byte
    memcpy(&(ih->ttl),pm->packet_buffer+pm->pbp,1);
    pm->pbp++;
    //protocol
    memcpy(&(ih->protocol),pm->packet_buffer+pm->pbp,1);
    pm->pbp++;
    //checksum
    memcpy(&(ih->header_checksum),pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    //source ip
    memcpy(ih->source_ip,pm->packet_buffer+pm->pbp,4);
    pm->pbp+=4;
    //dest ip
    memcpy(ih->destination_ip,pm->packet_buffer+pm->pbp,4);
    pm->pbp+=4;
    //calculate payload size
    pm->payload_size = ntohs(ih->total_length) - ((ih->ihl*32)/8);
    return 1;
}

int load_tcp_header_s(Packet_Meta pm, TCP_Header th){
    if(!pm || !th){
        fprintf(stderr, "Either Packet_Meta or TCP_Header is \
        null at loading tcp header\n");
        return 0;
    }
    //read in source port
    memcpy(&th->source_port, pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    //read in dest port
    memcpy(&th->destin_port, pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    //read in sequence number
    memcpy(&th->seq_num, pm->packet_buffer+pm->pbp, 4);
    pm->pbp+=4;
    //read in the ack number
    memcpy(&th->ack_number, pm->packet_buffer+pm->pbp, 4);
    pm->pbp+=4;
    uint8_t temp;
    memcpy(&temp, pm->packet_buffer+pm->pbp, 1);
    pm->pbp++;
    //ns flag
    th->ns = 0x1 & temp;
    temp >>= 1;
    //reserved should be zero
    th->reserved = 0x7 & temp;
    temp >>= 3;
    //data_offset
    th->data_offset = 0xF & temp;
    memcpy(&temp, pm->packet_buffer+pm->pbp, 1);
    pm->pbp++;
    //the rest of the flags
    th->fin = 0x1 & temp;temp>>=1;
    th->syn = 0x1 & temp;temp>>=1;
    th->rst = 0x1 & temp;temp>>=1;
    th->psh = 0x1 & temp;temp>>=1;
    th->ack = 0x1 & temp;temp>>=1;
    th->urg = 0x1 & temp;temp>>=1;
    th->ece = 0x1 & temp;temp>>=1;
    th->cwr = 0x1 & temp;temp>>=1;
    //win_size
    memcpy(&th->win_size, pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    //checksum
    memcpy(&th->check, pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    //urgent pointer
    memcpy(&th->urgent_point, pm->packet_buffer+pm->pbp, 2);
    pm->pbp+=2;
    //size of options
    unsigned o_size = ((th->data_offset * 32) / 8) - 20;
    th->options = (uint8_t*)calloc(o_size, sizeof(uint8_t));
    memcpy(th->options, pm->packet_buffer+pm->pbp, o_size);
    pm->pbp+=o_size;
    //recalculate payload size
    pm->payload_size = pm->payload_size - ((th->data_offset * 32) / 8);

    return 1;
}

int load_udp_header_s(Packet_Meta pm, UDP_Header uh){
    if(!pm || !uh){
        fprintf(stderr, "Either Packet_Meta or UDP_Header is \
        null at loading udp header\n");
        return 0;
    }
    memcpy(&uh->source_port,pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    memcpy(&uh->destin_port,pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    memcpy(&uh->length,pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;
    memcpy(&uh->check,pm->packet_buffer+pm->pbp,2);
    pm->pbp+=2;

    //recalculate payload size
    pm->payload_size = ntohs(uh->length) - 8;

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
// display functions - ip
//-----------------------------------------------------
void di_version(Packet p){
    printf("%u",p->ih->version);
}

void di_headerlen(Packet p){
    printf("%u (%u bytes)",p->ih->ihl,((p->ih->ihl)*32)/8);
}

void di_dscp(Packet p){
    uint8_t dsc = 0; dsc = p->ih->dscp & 0x3f;
    uint8_t temp = p->ih->dscp; temp >>= 6;
    uint8_t ecn = 0; ecn = temp & 0x3;
    printf("DSC: %u ECN: %u", dsc, ecn);
}

void di_totlen(Packet p){
    printf("%u", ntohs(p->ih->total_length));
}

void di_ident(Packet p){
    printf("0x%04x", ntohs(p->ih->identification));
}

void di_flags(Packet p){
    printf("(0x%02x) Reserved: %u, Don't fragment: %u, More fragments: %u", \
        p->ih->flags, p->ih->flags&0x4, p->ih->flags&0x2, p->ih->flags&0x1);
}

void di_fragoff(Packet p){
    printf("%u", p->ih->fragment_offset);
}

void di_ttl(Packet p){
    printf("%u", p->ih->ttl);
}

void di_protocol(Packet p){
    printf("%u", p->ih->protocol);
}

void di_headcheck(Packet p){
    printf("0x%04x", ntohs(p->ih->header_checksum));
}

void di_source(Packet p){
    for(int byte = 0; byte<4; byte++){
        if(byte<3)
            printf("%u:", p->ih->source_ip[byte]);
        else
            printf("%u", p->ih->source_ip[byte]);
    }
}

void di_dest(Packet p){
    for(int byte = 0; byte<4; byte++){
        if(byte<3)
            printf("%u:", p->ih->destination_ip[byte]);
        else
            printf("%u", p->ih->destination_ip[byte]);
    }
}

//-----------------------------------------------------
// display functions - tcp
//-----------------------------------------------------

void dt_sport(Packet p){
    printf("%u", ntohs(p->th->source_port));
}

void dt_dport(Packet p){
    printf("%u", ntohs(p->th->destin_port));
}

void dt_seq(Packet p){
    printf("%u", ntohl(p->th->seq_num));
}

void dt_ack(Packet p){
    printf("%u", ntohl(p->th->ack_number));
}

void dt_reserved(Packet p){ // should be zero
    printf("%u", p->th->reserved);
}

void dt_data_offset(Packet p){
    printf("%u", p->th->data_offset);
}

void dt_flags(Packet p){
    printf("\tns:  %d\
    \n\tcwr: %d\
    \n\tece: %d\
    \n\turg: %d\
    \n\tack: %d\
    \n\tpsh: %d\
    \n\trst: %d\
    \n\tsyn: %d\
    \n\tfin: %d",
    p->th->ns,
    p->th->cwr,
    p->th->ece,
    p->th->urg,
    p->th->ack,
    p->th->psh,
    p->th->rst,
    p->th->syn,
    p->th->fin);
}

void dt_win_size(Packet p){
    printf("%u", ntohs(p->th->win_size));
}

void dt_check(Packet p){
    printf("0x%04x", ntohs(p->th->check));
}

void dt_urgent_point(Packet p){
    printf("%u", ntohs(p->th->urgent_point));
}

void dt_options(Packet p){
    unsigned osize = ((p->th->data_offset * 32) / 8) - 20;
    for(unsigned byte = 1; byte < osize+1; byte++){
        printf("%02x ", p->th->options[byte-1]);
        if(byte%4==0&&byte!=osize)
            printf("\n\t");
    }
}

//-----------------------------------------------------
// display fucntions - udp
//-----------------------------------------------------
void du_sport(Packet p){
    printf("%u", ntohs(p->uh->source_port));
}

void du_dport(Packet p){
    printf("%u", ntohs(p->uh->destin_port));
}

void du_length(Packet p){
    printf("%u", ntohs(p->uh->length));
}

void du_check(Packet p){
    printf("0x%04x", ntohs(p->uh->check));
}

//-----------------------------------------------------
// payload
//-----------------------------------------------------

int load_payload_f(Packet p, Packet_Meta pm){
    if(!p->ih)
        fprintf(stderr,"Warning; ip header is unloaded, continuing anyway.\n");
    if(!p || !pm){
        fprintf(stderr,"Packet or packet meta is NULL at load payload\n");
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

int load_payload_s(Packet p, Packet_Meta pm){
    if(!p->ih)
        fprintf(stderr,"Warning; ip header is unloaded, continuing anyway.\n");
    if(!p || !pm){
        fprintf(stderr,"Packet or packet meta is NULL at load payload\n");
        return 0;
    }
    p->payload = (uint8_t*)calloc(pm->payload_size,sizeof(uint8_t));
    if(!p->payload){
        fprintf(stderr,"Calloc failed at allocating payload\n");
        return 0;
    }
    memcpy(p->payload,pm->packet_buffer+pm->pbp,pm->payload_size);
    pm->pbp+=pm->payload_size;

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
        if(p->payload[byte-1] < 32 || p->payload[byte-1] >= 127)
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

//-----------------------------------------------------
// destruction
//-----------------------------------------------------
int destroy_packet(Packet p){
    if(!p){
        fprintf(stderr,"Packet is Null at destruction\n");
        return 0;
    }
    if(p->payload)
        free(p->payload);
    if(p->ih){
        if(p->ih->source_ip)
            free(p->ih->source_ip);
        if(p->ih->destination_ip)
            free(p->ih->destination_ip);
        free(p->ih);
    }
    if(p->eh){
        if(p->eh->destination)
            free(p->eh->destination);
        if(p->eh->source)
            free(p->eh->source);
        free(p->eh);
    }
    if(p->th){
        if(p->th->options)
            free(p->th->options);
        free(p->th);
    }
    if(p->uh)
        free(p->uh);
    free(p);
    return 1;
}


int destructor(Packet_Meta pm, Packet p){
    if(!pm || !p){
        fprintf(stderr,"Packet meta and/or packet are Null at destruction\n");
        return 0;
    }
    if(pm->packet){
        fclose(pm->packet);
        free(pm->packet_buffer);
    }
    destroy_packet(p);
    free(pm);
    return 1;
}

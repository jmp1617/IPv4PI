//----------------------------------------------------
//
// Displays info about ethernet frame and ipv4 packet 
// in a human readable form
//
// uses ipv4lib
// 
//----------------------------------------------------

#include "ipv4lib.h"

void print_u(){
    fprintf(stderr,"USAGE: packet_info [name] [e] [fcs] [pre]\n \
            \tname: filename of .bin packet data\n \
            \te: 1 or 0, ethernet frame presence\n \
            \tfcs: 1 or 0, frame checksum presence\n \
            \tpre: 1 or 0, preamble and sync presence\n");
}

int main(int args, char* argv[]){
    if(args != 5){
        print_u();
        return 1;
    }
    else{
        printf("INIT\n");
        // Create Packet metadata
        Packet_Meta pm = create_packet_meta();
        // Create Packet data store
        Packet p = create_packet();
        //init packet meta
        init_md_f(pm, argv[1], strtol(argv[2],NULL,10), strtol(argv[3],NULL,10), strtol(argv[4],NULL,10), 0, 0);
        //read in eth header if it exists
        if(pm->ethernet_flag){
            printf("READING IN ETHERNET HEADER\n");
            load_eII_header_f(pm, p->eh); 
        }
        printf("READING IN IP HEADER\n");
        
        printf("\n\n----Ethernet Header----\n");
        printf("Destination MAC: ");de_destination(p);
        printf("\nSource MAC: ");de_source(p);
        printf("\nType: ");de_ethtype(p);
        printf("\nFrame checksum: ");de_fcs(p);
        printf("\n-----------------------\n\n");
    }
}

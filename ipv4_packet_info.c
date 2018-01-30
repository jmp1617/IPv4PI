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
        // Create Packet metadata
        Packet_Meta pm = create_packet_meta();
        // Create Packet data store
        Packet p = create_packet();
        //init packet meta
        init_md_f(pm, argv[1], strtol(argv[2],NULL,10), strtol(argv[3],NULL,10), strtol(argv[4],NULL,10), 0, 0);
        //read in eth header if it exists
        if(pm->ethernet_flag){
            load_eII_header_f(pm, p->eh); 
        }
        load_ip_header_f(pm, p->ih);
        load_payload_f(p, pm);

        printf("Total bytes: %d\n",pm->byte_count);

        printf("\n----Ethernet Header----\n");
        printf("Destination MAC: ");de_destination(p);
        printf("\nSource MAC: ");de_source(p);
        printf("\nType: ");de_ethtype(p);
        printf("\nFrame checksum: ");de_fcs(p);
        printf("\n-----------------------\n\n");

        printf("-------IPv4 Header-------\n");
        printf("Version: ");di_version(p);
        printf("\nHeader Length: ");di_headerlen(p);
        printf("\nDSCP: ");di_dscp(p);
        printf("\nTotal Length: ");di_totlen(p);
        printf("\nIdentification: ");di_ident(p);
        printf("\nFlags: ");di_flags(p);
        printf("\nFragment offset: ");di_fragoff(p);
        printf("\nTtl: ");di_ttl(p);
        printf("\nProtocol: ");di_protocol(p);
        printf("\nHeader Checksum: ");di_headcheck(p);
        printf("\nSource: ");di_source(p);
        printf("\nDestination: ");di_dest(p);
        printf("\n-------------------------\n");

        printf("\n---------Payload---------\n");
        printf("Payload byte count: %d\n",pm->payload_size);
        printf("Payload:\n");display_payload_x(p,pm);
    }
}

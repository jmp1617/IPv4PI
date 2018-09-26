#include "ipv4lib.h"

int main(){

    Packet p;
    Packet_Meta pm = create_packet_meta();
    // Create Packet metadata
    init_md_s(pm,1,0,0,0,0);

    int counter = 0;
    while(1){
        // Create Packet data store
        p = create_packet();
        //load in a packet
        socket_to_buffer(pm);
        //load ethernet header
        load_eII_header_s(pm, p->eh);
        load_ip_header_s(pm,p->ih);
        //reset the pointer since we only want eth
        pm->pbp = 0;
        printf("\n\n\nPacket number: %d\nTotal bytes: %d\n",counter,pm->byte_count);
        
        printf("\n--------Ethernet Header-------\n");
        printf("Destination MAC: ");de_destination(p);
        printf("\nSource MAC: ");de_source(p);
        printf("\nType: ");de_ethtype(p);
        printf("\nFrame checksum: ");de_fcs(p);
        printf("\n------------------------------\n");
        
        printf("\n----------IPv4 Header---------\n");
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
        printf("\n------------------------------\n");

        destroy_packet(p);
        counter++;
    }

    destructor(pm,p);
}

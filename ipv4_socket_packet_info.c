#include "ipv4lib.h"

int main(){

    Packet p;
    Packet_Meta pm = create_packet_meta();
    // Create Packet metadata
    init_md_s(pm,1,0,0,0,0);

    while(1){
        // Create Packet data store
        p = create_packet();
        //load in a packet
        socket_to_buffer(pm);
        //load ethernet header
        load_eII_header_s(pm, p->eh);
        pm->pbp = 0; //reset the pointer since we only want eth 

        printf("Total bytes: %d\n",pm->byte_count);

        if(pm->ethernet_flag){
            printf("\n--------Ethernet Header-------\n");
            printf("Destination MAC: ");de_destination(p);
            printf("\nSource MAC: ");de_source(p);
            printf("\nType: ");de_ethtype(p);
            printf("\nFrame checksum: ");de_fcs(p);
            printf("\n------------------------------\n");
        }
    }

    destructor(pm,p);
}

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
        if(p->ih->protocol == 6){
            p->th = create_tcp_header();
            load_tcp_header_s(pm, p->th);
        }
        else if(p->ih->protocol == 17){
            p->uh = create_udp_header();
            load_udp_header_s(pm, p->uh);
        }
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

        if(p->ih->protocol == 6){
            printf("\n-----------TCP----------------\n");
            printf("Source Port: ");dt_sport(p);
            printf("\nDestination Port: ");dt_dport(p);
            printf("\nSequence Number: ");dt_seq(p);
            printf("\nAcknowledgment Number: ");dt_ack(p);
            printf("\nData Offset: ");dt_data_offset(p);
            printf("\nReserved: ");dt_reserved(p);
            printf("\nFlags:");dt_flags(p);
            printf("\nWindow Size: ");dt_win_size(p);
            printf("\nChecksum: ");dt_check(p);
            printf("\nUrgent Pointer: ");dt_urgent_point(p);
            printf("\nOption Bytes:\n\t");dt_options(p);
            printf("\n------------------------------\n\n");
        }
        else if(p->ih->protocol == 17){
            printf("\n------------UDP---------------\n");
            printf("Source Port: ");du_sport(p);
            printf("\nDestination Port: ");du_dport(p);
            printf("\nLength: ");du_length(p);
            printf("\nChecksum: ");du_check(p);
            printf("\n------------------------------\n\n");
        }

        destroy_packet(p);
        counter++;
    }

    destructor(pm,p);
}

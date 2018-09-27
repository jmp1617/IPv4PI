#include "ipv4lib.h"
// Dumps network traffic to stdout
int main(){
    Packet p;
    Packet_Meta pm = create_packet_meta();
    // Create Packet metadata
    init_md_s(pm,1,0,0,0,0);
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
    if(pm->payload_size)
        load_payload_s(p, pm);
    //reset the pointer
    reset_pbp(pm);

    write_to_packet_buffer(pm,p);

    destructor(pm,p);
}

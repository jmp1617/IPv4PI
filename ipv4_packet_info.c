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
        //init packet meta
        init_md_f(pm, argv[1], strtol(argv[2],NULL,10), strtol(argv[3],NULL,10), strtol(argv[4],NULL,10), 0, 0);
    }
}

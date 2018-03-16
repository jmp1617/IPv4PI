//A small program to generate a selection of bytes and rewrite to the file
//
//

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

void print_usage(){
    fprintf(stderr, "USAGE: byte_extract [file] [number of bytes to read in] \
    [start index to write out] [end index to write out] [output file]\n");
}

void extract(int rbytes, int sindex, int eindex, char* file, char* out){
   FILE* fp = fopen(file, "r");
   FILE* op = fopen(out, "w");
   uint8_t bytes[rbytes];

   fread(bytes, 1, rbytes, fp);
   fclose(fp);
   for(int b = sindex; b < eindex; b++)
       fwrite(&bytes[b],1,1,op);
   fclose(op);
}

int main(int argc, char* argv[]){
    if( argc != 6){
        print_usage();
        return 1;
    }
    else{
        extract( strtol(argv[2],NULL,10), strtol(argv[3],NULL,10), \
            strtol(argv[4],NULL,10), argv[1], argv[5]);
    }
    return 0;
}

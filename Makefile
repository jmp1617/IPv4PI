
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	CC = gcc
	CFLAGS = -Wall -Wextra -pedantic
endif
ifeq ($(UNAME_S),Darwin)
	CC = clang
	CFLAGS = -Wall -Wextra -pedantic
endif

default: packet_info

packet_info: ipv4lib.h ipv4lib.c ipv4_packet_info.c
	$(CC) $(CFLAGS) -o packet_info ipv4lib.h ipv4lib.c ipv4_packet_info.c

byte_extract: byte_extract.c
	$(CC) $(CFLAGS) -o byte_extract byte_extract.c

payload_inject: ipv4lib.h ipv4lib.c ipv4_payload_inject.c
	$(CC) $(CFLAGS) -o payload_inject ipv4lib.h ipv4lib.c ipv4_payload_inject.c

socket_packet_info: ipv4lib.h ipv4lib.c ipv4_socket_packet_info.c
	$(CC) $(CFLAGS) -o socket_packet_info ipv4lib.h ipv4lib.c ipv4_socket_packet_info.c

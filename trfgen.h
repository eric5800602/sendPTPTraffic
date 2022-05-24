#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "ptp_message.h"

#define NSEC_SLEEP(ns)                                                         \
  (struct timespec) { (ns) / 1000000000ULL, (ns) % 1000000000ULL }

#define PACKET_SIZE           4096
#define GTPU_PORT             2152
#define GTP_EXT_HDR_OFFSET    4
#define PAYLOAD_HEADER_OFFSET 44

int packet_size       = 1024;
int NUMBER_OF_THREADS = 5;
int NUMBER_OF_PACKETS = 1000;
uint32_t TEID         = 0x000004d2;

struct gtp {
  uint8_t  flags;
  uint8_t  msg;
  uint16_t len;
  uint32_t teid;
  uint16_t sequence;
};

struct gtp_ext {
  uint8_t  len;
  uint8_t  pdu_type;
  uint8_t  qfi;
  uint8_t  next_ext_type;
};

/*  IP Header  */
struct ip {
  uint8_t  ver_hlen;   /* Header version and length (dwords). */
  uint8_t  service;    /* Service type. */
  uint16_t length;    /* Length of datagram (bytes). */
  uint16_t ident;     /* Unique packet identification. */
  uint16_t fragment;  /* Flags; Fragment offset. */
  uint8_t  timetolive; /* Packet time to live (in network). */
  uint8_t  protocol;   /* Upper level protocol (UDP, TCP). */
  uint16_t checksum;  /* IP header checksum. */
  uint32_t src_addr;  /* Source IP address. */
  uint32_t dest_addr; /* Destination IP address. */
};

/*  TCP Header  */
struct tcp {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  //  uint8_t tcp_res1:4;
  uint8_t  tcp_hdr_len : 4;
  uint8_t  tcp_fin : 1;
  uint8_t  tcp_syn : 1;
  uint8_t  tcp_rst : 1;
  uint8_t  tcp_psh : 1;
  uint8_t  tcp_ack : 1;
  uint8_t  tcp_urg : 1;
  //	uint8_t tcp_res2:2;
  uint16_t tcp_win_size;
  uint16_t tcp_chk;
  uint16_t tcp_urg_ptr;
};

/*  UDP Header  */
struct udp {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t hdr_len;
  uint16_t checksum;
  char data[PACKET_SIZE - PAYLOAD_HEADER_OFFSET]; // Use this field to vary final
                                              // packet size char *data;
  // char *data1;
};

struct final_packet {
  struct gtp     p1;
  struct ethhdr p2;
  struct ptp_delay_req p3;
};

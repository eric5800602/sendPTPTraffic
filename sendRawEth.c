/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "trfgen.h"

#define MY_DEST_MAC0	0x01
#define MY_DEST_MAC1	0x80
#define MY_DEST_MAC2	0xC2
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x0E

#define DEFAULT_IF	"ens18"
#define BUF_SIZ		1024

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
    
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = 0x88f7;
    eh->ether_type = htons(eh->ether_type);
	tx_len += sizeof(struct ether_header);

      /* PTP */
    struct ptp_delay_req ptp_delay_req_h;
    memset(&ptp_delay_req_h, 0, sizeof(struct ptp_delay_req));
    ptp_delay_req_h.hdr.msg_type = 0x12;
    ptp_delay_req_h.hdr.ptp_ver = 0x02;
    ptp_delay_req_h.hdr.msg_len = 0x0036;
    ptp_delay_req_h.hdr.msg_len = htons(ptp_delay_req_h.hdr.msg_len);
    ptp_delay_req_h.hdr.domain_num = 0;
    ptp_delay_req_h.hdr.res = 0;
    ptp_delay_req_h.hdr.flags = 0;
    ptp_delay_req_h.hdr.corr_field = 0;
    ptp_delay_req_h.hdr.res1 = 0;
    u8 tmp[8] = {0x76,0x91,0x5c,0xff,0xfe,0x26,0x94,0xe8};
    memcpy(&ptp_delay_req_h.hdr.src_port_id.clock_identity,tmp,sizeof(tmp));
    ptp_delay_req_h.hdr.src_port_id.port_number = 0x0001;
    ptp_delay_req_h.hdr.src_port_id.port_number = htons(ptp_delay_req_h.hdr.src_port_id.port_number);
    ptp_delay_req_h.hdr.seq_id = 0x001d;
    ptp_delay_req_h.hdr.seq_id = htons(ptp_delay_req_h.hdr.seq_id);
    ptp_delay_req_h.hdr.control = 0x05;
    ptp_delay_req_h.hdr.log_mean_msg_interval = 0;
    memset(ptp_delay_req_h.origin_tstamp, 0, sizeof(ptp_delay_req_h.origin_tstamp));

	/* Packet data */
    memcpy(sendbuf+tx_len,&ptp_delay_req_h,sizeof(ptp_delay_req_h));
    tx_len += sizeof(ptp_delay_req_h);

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");
    else
        printf("%d\n",tx_len);
	return 0;
}
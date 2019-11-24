/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
tination: DE:3D:88:DD:91:17
	source: 4E:30:35:6F:49:46
	type: 2054
Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
  uint16_t packet_type = ntohs(eth_header->ether_type);

  if(is_valid_arp_packet(packet, len, packet_type)) {
    handle_arp_packet(sr, packet, len, interface);
  } else if (is_valid_ip_packet(packet, len, packet_type)) {
    handle_ip_packet(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  printf("-----Handling ip packet-----\n");

  struct sr_ip_hdr *ip_packet = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

  uint32_t ip_src = ip_packet->ip_src;
  uint32_t ip_dst = ip_packet->ip_dst;

  struct sr_if* dst_interface = sr_get_interface_by_ip(sr, ip_dst);
  struct sr_rt *lpm = find_lpm(sr->routing_table, ip_dst);
  if(dst_interface == NULL && lpm == NULL) {
    /* ICMP net unreachable*/
    printf("-----ip dest unreachable-----\n");
    send_icmp_error_msg(sr, 3, 0, ip_src, (uint8_t*)ip_packet);
  } else {
    /* packet for me*/
    if(dst_interface != NULL) {
      uint8_t ip_protocol = ip_packet->ip_p;
      if(ip_protocol == ip_protocol_icmp){
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        /* if is ICMP echo req, send echo reply*/
        if(icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) {
          send_icmp_echo_reply(sr, packet, len, interface, icmp_header, ip_packet);
        }
      } else {
        /* not icmp packet, send icmp port unreachable*/
        send_icmp_error_msg(sr, 3, 3, ip_src, (uint8_t*)ip_packet);
      }
    /* packet not for me, forward packet */
    } else {
      ip_packet->ip_ttl--;
      if(ip_packet->ip_ttl <= 0) {
        /*time exceeded*/
        send_icmp_error_msg(sr, 11, 0, ip_src, (uint8_t*)ip_packet);
      } else {
        ip_packet->ip_sum = calc_ip_checksum(ip_packet);
        forward_packet(sr, lpm, packet, len);
      }
    }
  }
}


int is_valid_arp_packet(uint8_t * packet/* lent */,  unsigned int len, uint16_t packet_type) {
    printf("-----Validating arp packet-----\n");
    if(packet_type == ethertype_arp) {
      /* packet is type arp, validate length*/
      if(len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
        /* packet length is valid*/
        return 1;
      }
    }
    return 0;
  }

int is_valid_ip_packet(uint8_t * packet/* lent */,  unsigned int len, uint16_t packet_type) {
  printf("-----Validating ip packet-----\n");
  if (packet_type == ethertype_ip) {
    if(len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
      /*length is valid, validate check sum*/
      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      uint32_t calculated_checksum = calc_ip_checksum(ip_header);
      if(ip_header->ip_sum == calculated_checksum) {
        printf("-----Checksum is correct-----\n");
        return 1;
      }
    }
  }
  return 0;
}

void send_icmp_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        sr_icmp_hdr_t *icmp_header,
        struct sr_ip_hdr *ip_header) 
{
  /*update ip header*/
  struct sr_if *cur_interface = sr_get_interface(sr, interface);
  ip_header->ip_dst = ip_header->ip_src;
  ip_header->ip_src = cur_interface->ip;
  ip_header->ip_sum = calc_ip_checksum(ip_header);
  /*update icmp header*/
  icmp_header->icmp_type = 0;
  icmp_header->icmp_code = 0;
  icmp_header->icmp_sum = calc_icmp_checksum(icmp_header);
  /*update ethernet header*/
  sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) packet;
  uint8_t* e_source_addr = e_header->ether_shost;
  memcpy(e_header->ether_shost, e_header->ether_dhost, ETHER_ADDR_LEN);
  memcpy(e_header->ether_dhost, e_source_addr, ETHER_ADDR_LEN);
  int packet_sent = sr_send_packet(sr, packet, len, cur_interface->name);
  if(packet_sent == 0) {
    printf("-----packet successfully sent-----\n");
  }
}

void send_icmp_error_msg(struct sr_instance *sr,
        uint8_t type,
        uint8_t code,
        uint32_t ip_dst,
        uint8_t *ip_packet)
{
  /*initialize new packet*/
  int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *new_packet = malloc(len);
  /*initialize packet headers*/
  sr_ethernet_hdr_t *new_eth_header = (sr_ethernet_hdr_t *) new_packet;
  sr_ip_hdr_t *new_ip_header = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *new_icmp_header = (sr_icmp_t3_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  /*set icmp headers and icmp check sum*/
  new_icmp_header->icmp_type = type;
  new_icmp_header->icmp_code = code;
  memcpy(new_icmp_header->data, ip_packet, ICMP_DATA_SIZE);
  new_icmp_header->icmp_sum = calc_icmp_checksum((sr_icmp_hdr_t *) new_icmp_header);
  /*set ip headers*/
  struct sr_rt *lpm = find_lpm(sr->routing_table, ip_dst);
  if(lpm != NULL) {
    struct sr_if *cur_interface = sr_get_interface(sr, lpm->interface);
    new_ip_header->ip_tos = 0;
    new_ip_header->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    new_ip_header->ip_id = htons(0);
    new_ip_header->ip_off = htons(IP_DF);
    new_ip_header->ip_ttl = 64;
    new_ip_header->ip_p = ip_protocol_icmp;
    new_ip_header->ip_src = cur_interface->ip;
    new_ip_header->ip_dst = ip_dst;
    new_ip_header->ip_sum = calc_ip_checksum(new_ip_header);
  }
  new_eth_header->ether_type = htons(ethertype_ip);
  forward_packet(sr, lpm, new_packet, len);
}

void forward_packet(struct sr_instance *sr, struct sr_rt *lpm, uint8_t * packet, unsigned int len) {
  printf("forward pack function\n");
  if(lpm != NULL) {
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
    uint32_t next_hop_ip = (uint32_t) lpm->gw.s_addr;
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    /* arp entry found, modify mac and send packet */
    if(arp_entry) {
      printf("forward pack sending packet\n");
      struct sr_if *interface = sr_get_interface(sr, (const char *) (lpm->interface));
      memcpy(eth_header->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eth_header->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, interface->name);
    } else {
      /* send arp request */
      printf("sending arp req from forward pack\n");
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, lpm->interface); /*remove the & from &(lpm->interface)*/
      sr_arp_send_request(sr, arp_req);
    }
  }
printf("forward did nothing\n");
}


/*--------------------------------------------------------------------- 
 * Given an interface ip return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if* sr_get_interface_by_ip(struct sr_instance* sr, uint32_t ip)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(ip);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(if_walker->ip == ip)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface -- */

/*--------------------------------------------------------------------- 
 * Method: find_lpm(..)
 *
 * find the longest prefix match entry given rounting table and ip
 *
 *---------------------------------------------------------------------*/
struct sr_rt *find_lpm(struct sr_rt *r_table, uint32_t ip_dst) {
  
  struct sr_rt *lpm_rt = NULL;
  uint32_t lpm = 0;

  while(r_table != NULL) {
    struct in_addr mask = r_table->mask;
    /*TODO: Verify this check works*/
    uint32_t temp = r_table->mask.s_addr & ip_dst;
    uint32_t temp1 = r_table->mask.s_addr;
    uint32_t temp2 = r_table->dest.s_addr;
    printf("-----%u == %u, temp2 = %u-----\n",temp, temp1, temp2);
    /* if mask matches ip_dst */
    if((mask.s_addr & ip_dst) == r_table->dest.s_addr) {
      if(mask.s_addr > lpm) {
        lpm = mask.s_addr;
        lpm_rt = r_table;
      }
    }
    r_table = r_table->next;
  }
  return lpm_rt;
}

/*--------------------------------------------------------------------- 
 * Method: calc_ip_checksum(..)
 *RP reply----------

 * calculated ip checksum
 *
 *---------------------------------------------------------------------*/
uint32_t calc_ip_checksum(sr_ip_hdr_t *ip_header) {
      /*original checksum*/
      uint16_t ip_checksum = ip_header -> ip_sum;
      ip_header->ip_sum = 0;
      /*calculate checksum of ip packet*/
      uint16_t calculated_checksum = cksum(ip_header, sizeof(sr_ip_hdr_t));
      /*restore the original checksum*/
      ip_header->ip_sum = ip_checksum;
      return calculated_checksum;
}

/*--------------------------------------------------------------------- 
 * Method: calc_icmp_checksum(..)
 *
 * calculated icmp checksum
 *
 *---------------------------------------------------------------------*/
uint32_t calc_icmp_checksum(sr_icmp_hdr_t *icmp_header) {

      uint16_t icmp_checksum = icmp_header -> icmp_sum;
      icmp_header->icmp_sum = 0;
      uint16_t calculated_checksum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
      icmp_header->icmp_sum = icmp_checksum;
      return calculated_checksum;
}


void handle_arp_packet(struct sr_instance* sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	printf("---------Got an ARP Packet----------\n");
  /* Packet Size */
  int ARP_Packet_Len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  /* Getting Ethernet Header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  /* Getting ARP Header */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  /* Getting OP_Code */
  unsigned int ar_op_code = ntohs(arp_hdr->ar_op);
  /* Check if it is for my interfac */
  struct sr_if *my_if = sr_get_interface(sr, interface);
  if(ar_op_code == arp_op_request){
    printf("---------ARP request----------\n");
    /* One of Mine interface */
    if(my_if){
      printf("---------ARP request for my interface----------\n");
      uint8_t *reply_arp = (uint8_t *)malloc(ARP_Packet_Len);
      /* Creating Reply Arp Header */
      sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_arp + sizeof(sr_ethernet_hdr_t));
      /* Creating reply Ethernet Header */
      sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_arp;
      reply_eth_hdr->ether_type = htons(ethertype_arp);
      memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(reply_eth_hdr->ether_shost, (uint8_t *) my_if->addr, ETHER_ADDR_LEN);
      /* Copying old ARP packet to new ARP packet*/
      reply_arp_hdr->ar_hrd = htons(1);;
      reply_arp_hdr->ar_pro = htons(2048);
      reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
      reply_arp_hdr->ar_pln = 4;
      reply_arp_hdr->ar_op = htons(arp_op_reply);
      reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
      /* Changing Variable around*/
      reply_arp_hdr->ar_sip = my_if->ip; 
      memcpy(reply_arp_hdr->ar_sha, my_if->addr, ETHER_ADDR_LEN);
      memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      printf("-----------------ARP Reply created and sent------------------\n");
      sr_send_packet(sr, reply_arp, ARP_Packet_Len, my_if->name);
      free(reply_arp);  
 			}
		else{
      printf("---------Not for my Router Dropping------------\n");
      return;
    }
  }		
	else if(ar_op_code == arp_op_reply){
    printf("---------ARP reply----------\n");
    /* Insert it to my ARP cache */
    struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    /* Sending outstanding packet in Queue */
    if(req){
      struct sr_packet *cPacket = req->packets;
			/* Looping through packet in req */
			while(cPacket){
				/* Creating ethernet header */
				uint8_t *reply_packet = cPacket->buf;
				struct sr_if *cInterface = sr_get_interface(sr, cPacket->iface);
				sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_packet;
				memcpy(reply_eth_hdr->ether_shost, cInterface->addr, ETHER_ADDR_LEN);
				memcpy(reply_eth_hdr->ether_dhost,  arp_hdr->ar_sha, ETHER_ADDR_LEN);
				sr_send_packet(sr, reply_packet, cPacket->len, cInterface->name);
				free(reply_packet);
				cPacket = cPacket->next;
       	}
    }
  }
	else{
    printf("---------Invalid OPCode Dropping----------\n");
    return;
  }
}

/*Sending an ARP request */
void sr_arp_send_request(struct sr_instance *sr, struct sr_arpreq *req){
  printf("---------Sending ARP request----------\n");
  /* Paciket Size */
  int ARP_Packet_Len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  struct sr_if *interface = sr_get_interface(sr, (req->packets)->iface);
	/* Creating reply ethernet header */
	uint8_t *req_arp = (uint8_t *)malloc(ARP_Packet_Len);
  sr_arp_hdr_t *req_arp_hdr = (sr_arp_hdr_t *)(req_arp + sizeof(sr_ethernet_hdr_t));
	/* Creating reply ethernet header */
	sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *) req_arp;
	memset(req_eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(req_eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	req_eth_hdr->ether_type = htons(ethertype_arp);
	/* Creating a ARP packet */
	req_arp_hdr->ar_hrd = htons(1);
	req_arp_hdr->ar_pro = htons(2048);
	req_arp_hdr->ar_hln = ETHER_ADDR_LEN;
	req_arp_hdr->ar_pln = 4;
	req_arp_hdr->ar_op = htons(arp_op_request);
	req_arp_hdr->ar_tip = req->ip;
	req_arp_hdr->ar_sip = interface->ip;    
  memcpy(req_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
  memset(req_arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
  sr_send_packet(sr, req_arp, req->packets->len, interface->name);
  free(req_arp);
} 

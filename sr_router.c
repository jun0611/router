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
        int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + icmp_offset);
        /* if is ICMP echo req, send echo reply*/
        if(icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) {
          send_icmp_echo_reply(sr, packet, len, interface, icmp_header, ip_packet);
        }
      } else {
        /* send icmp port unreachable*/
        send_icmp_error_msg(sr, 3, 3, ip_src, (uint8_t*)ip_packet);
      }
    /* packet not for me, forward packet */
    } else {
      ip_packet->ip_ttl--;
      if(ip_packet->ip_ttl <= 0) {
        send_icmp_error_msg(sr, 11, 0, ip_src, (uint8_t*)ip_packet);
      } else {
        ip_packet->ip_sum = calc_ip_checksum(ip_packet);
        forward_packet(sr, lpm, packet, len);
      }
    }
  }
}


int is_valid_arp_packet(uint8_t * packet/* lent */,  unsigned int len, uint16_t packet_type) {
    printf("-----Validating packet-----\n");

    if(packet_type == ethertype_arp) {
      /* packet is type arp, validate length*/
      printf("-----Validating length of arp packet-----\n");
      if(len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
        /* packet length is valid*/
        printf("-----valid arp length-----\n");
        return 1;
      }
    }
    return 0;
  }

int is_valid_ip_packet(uint8_t * packet/* lent */,  unsigned int len, uint16_t packet_type) {
  if (packet_type == ethertype_ip) {
    printf("-----Validating length of ip packet-----\n");
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
  int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  icmp_header->icmp_sum = calc_icmp_checksum(icmp_header, len - icmp_offset);
  /*update ethernet header*/
  sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) packet;
  uint8_t* e_source_addr = e_header->ether_shost;
  memcpy(e_header->ether_shost, e_header->ether_dhost, ETHER_ADDR_LEN);
  memcpy(e_header->ether_dhost, e_source_addr, ETHER_ADDR_LEN);
  int packet_sent = sr_send_packet(sr, packet, len, cur_interface);
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
  new_icmp_header->icmp_sum = calc_icmp_checksum(new_icmp_header, sizeof(sr_icmp_t3_hdr_t));
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
  if(lpm != NULL) {
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
    uint32_t next_hop_ip = (uint32_t) lpm->gw.s_addr;
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    /* arp entry found, modify mac and send packet */
    if(arp_entry) {
      struct sr_if *interface = sr_get_interface(sr, (const char *) (lpm->interface));
      memcpy(eth_header->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eth_header->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, interface);
    } else {
      /* send arp request */
      struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, &(lpm->interface));
      sr_arp_send_request(sr, arp_req);
    }
  }
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
    if((mask.s_addr & ip_dst) == mask.s_addr) {
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
 *
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
uint32_t calc_icmp_checksum(sr_icmp_hdr_t *icmp_header, unsigned int len) {

      uint16_t icmp_checksum = icmp_header -> icmp_sum;
      icmp_header->icmp_sum = 0;
      uint16_t calculated_checksum = cksum(icmp_header, len);
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
  printf("1\n");
  /* Getting Ethernet Header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  printf("2\n");
  /* Getting ARP Header */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  printf("3\n");
  /* Getting OP_Code */
  unsigned int ar_op_code = ntohs(arp_hdr->ar_op);
  printf("4\n");
  /* Check if it is for my interfac */
  struct sr_if *my_if = sr_get_interface(sr, interface/*Dest IP add */);
  printf("5\n");
  /* Check what kind of code */
  if(ar_op_code == arp_op_request){
    printf("---------ARP request----------\n");
    
    /* One of Mine interface */
    if(my_if){
      printf("---------ARP request for my interface----------\n");
      /* Look up the cache to insert if not in my cache*/
      
      uint8_t *reply_arp = (uint8_t *)malloc(ARP_Packet_Len);
      printf("6\n");
      /* Creating reply ethernet header */
      sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_arp;
      printf("7\n");
      sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_arp + sizeof(sr_ethernet_hdr_t));
      printf("8\n");
      reply_eth_hdr->ether_type = htons(ethertype_arp);
      printf("9\n");
      memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
      printf("10\n");
      memcpy(reply_eth_hdr->ether_shost, (uint8_t *) my_if->addr, ETHER_ADDR_LEN);
      printf("11\n");
      /* Creating a ARP packet */
      reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
      reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
      reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
      reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
     /* reply_arp_hdr->ar_sha = my_if->addr;*/
      reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
     /* reply_arp_hdr->ar_tha = arp_hdr->ar_sha;*/
      reply_arp_hdr->ar_sip = my_if->ip; 
      printf("12\n");
      reply_arp_hdr->ar_op = htons(arp_op_reply);      
      memcpy(reply_arp_hdr->ar_sha, my_if->addr, ETHER_ADDR_LEN);
      printf("13\n");
      memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      printf("14\n");
      /*reply_arp_hdr->ar_op = htons(arp_op_reply);
      printf("15\n");
      reply_arp_hdr->ar_tip = my_if->ip;
      printf("16\n");
      reply_arp_hdr->ar_sip = arp_hdr->ar_sip;
      printf("17\n");*/
     /* sr_send_packet(sr, reply_arp, ARP_Packet_Len, my_if->name);*/
      printf("18\n");
      /*free(reply_arp);*/
      printf("-----------------ARP Reply created and sent------------------\n");
      printf("given pack\n");
      print_hdrs(packet, len);
      printf("arp reply\n");
      print_hdrs(reply_arp, ARP_Packet_Len);
      sr_send_packet(sr, reply_arp, ARP_Packet_Len, my_if->name);   
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
    if(!req){
       struct sr_packet *cPacket = req->packets;
       uint8_t *reply_Packet;
       /* Looping through packet in req */
       while(!cPacket){
        /* Creating ethernet header */
        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) packet;
        reply_eth_hdr->ether_type = htons(ethertype_arp);
        memcpy(reply_eth_hdr->ether_shost, my_if->addr, ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr->ether_dhost, (uint8_t *) arp_hdr->ar_sha, ETHER_ADDR_LEN);
        reply_Packet = malloc(sizeof(uint8_t) * cPacket->len);
        memcpy(reply_Packet, cPacket, cPacket->len);
        sr_send_packet(sr, reply_Packet, cPacket->len, cPacket->iface);
        free(reply_Packet);
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
  /* Packet Size */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
  int ARP_Packet_Len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  struct sr_if *interface = sr_get_interface(sr, (req->packets)->iface);

  uint8_t *req_arp = (uint8_t *)malloc(ARP_Packet_Len);
      /* Creating reply ethernet header */
      sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *) req_arp;
      printf("7\n");
      sr_arp_hdr_t *req_arp_hdr = (sr_arp_hdr_t *)(req_arp + sizeof(sr_ethernet_hdr_t));
      printf("8\n");
      req_eth_hdr->ether_type = htons(ethertype_arp);
      printf("9\n");
      /* Creating a ARP packet */
      req_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
      req_arp_hdr->ar_pro = arp_hdr->ar_pro;
      req_arp_hdr->ar_hln = arp_hdr->ar_hln;
      req_arp_hdr->ar_pln = arp_hdr->ar_pln;

        req_arp_hdr->ar_op = htons(arp_op_request);
  req_arp_hdr->ar_tip = req->ip;
  req_arp_hdr->ar_sip = interface->ip;
 
      printf("12\n");
      req_arp_hdr->ar_op = htons(arp_op_reply);      
  /* Creating reply ethernet header */
  memcpy(req_eth_hdr->ether_dhost, interface->addr, ETHER_ADDR_LEN);
  memcpy(req_eth_hdr->ether_shost, (uint8_t*) 255, ETHER_ADDR_LEN);

  /* Creating a ARP packet */
  memcpy(req_arp_hdr->ar_sha, interface->addr,  sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(req_arp_hdr->ar_tha,(uint8_t *) 255,  sizeof(uint8_t) *ETHER_ADDR_LEN);
  sr_send_packet(sr, req_arp_hdr, (req->packets)->len, interface);
  free(req_arp);
  /*
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
   Creating ethernet header 
  eth_hdr->ether_type = htons(ethertype_arp);
  memcpy(eth_hdr->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost,(uint8_t *) 255, sizeof(uint8_t) * ETHER_ADDR_LEN);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));

  uint8_t *req_arp_hdr = (uint8_t *)malloc(arp_packet_len);
  memcpy(req_arp_hdr, arp_hdr, arp_packet_len);
  memcpy(req_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
  memcpy(req_arp_hdr->ar_tha,(uint8_t *) 255, ETHER_ADDR_LEN);
  req_arp_hdr->ar_code = arp_op_request;
  req_arp_hdr->tip = req->ip;
  req_arp_hdr->sip = interface->ip;
  req_arp_hdr->ar_hrd = 1;
  req_arp_hdr->ar_pro = 2048;
  req_arp_hdr->ar_hln = ETHER_ADDR_LEN;
  req_arp_hdr->ar_pln = 4;
  sr_send_packet(sr, req_arp_hdr, (req->packet)->len, interface);
  free(req_arp_hdr);
  */
} 

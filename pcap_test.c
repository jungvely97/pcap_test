#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

typedef struct EthernetHeader{
    unsigned char DesMac[6];
    unsigned char SrcMac[6];
    unsigned short Type;
}EthernetH;
typedef struct IPHeader{
    unsigned char Version : 4;
    unsigned char IHL : 4;
    unsigned char TOS;
    u_short TotalLen;
    unsigned short Identifi;
    unsigned char Flagsx : 1;
    unsigned char FlagsD : 1;
    unsigned char FlagsM : 1;
    unsigned int FO : 13;
    unsigned char TTL;
    unsigned char Protocal;
    unsigned short HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;
typedef struct TCPHeader{
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int SN;
    unsigned int AN;
    unsigned char Offset : 4;
    unsigned char Reserved : 4;
    unsigned char FlagsC : 1;
    unsigned char FlagsE : 1;
    unsigned char FlagsU : 1;
    unsigned char FlagsA : 1;
    unsigned char FlagsP : 1;
    unsigned char FlagsR : 1;
    unsigned char FlagsS : 1;
    unsigned char FlagsF : 1;
    unsigned short Window;
    unsigned short Check;
    unsigned short UP;
}TCPH;
typedef struct HttpH
{
    uint16_t HTP[16];
}HttpH;

void PrintEthernetHeader(const u_char *packet);
void PrintIPHeader(const u_char *packet);
void PrintTCPHeader(const u_char *packet);
void PrintHttpHeader(const uint8_t *packet);

void help(){
    printf("Write Interface Name\n");
    printf("Sample : pcap_test ens33\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2){
        help();
        exit(1);
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    IPH *tlen;
    u_int lengh;
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
        tlen = (IPH *)packet;
        lengh = htons(tlen->TotalLen) - (uint16_t)(tlen->IHL)*4;
        packet +=(uint16_t)(tlen->IHL)*4;
        PrintTCPHeader(packet);
        packet += ( u_char)lengh;
        PrintHttpHeader(packet);
    }

    pcap_close(handle);
    return 0;
}

void PrintEthernetHeader(const u_char *packet){
    EthernetH *eh;
    eh = (EthernetH *)packet;
    printf("\n======== Ethernet Header ========\n");
    printf("Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> DesMac[0],eh -> DesMac[1],eh -> DesMac[2],eh -> DesMac[3],eh -> DesMac[4],eh -> DesMac[5]);
    printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> SrcMac[0],eh -> SrcMac[1],eh -> SrcMac[2],eh -> SrcMac[3],eh -> SrcMac[4],eh -> SrcMac[5]);

}

void PrintIPHeader(const u_char *packet){
    IPH *ih;
    ih = (IPH *)packet;
    printf("======== IP Header ========\n");
    if (ih -> Protocal == 0x06) printf ("TCP\n");
    printf("Src IP  : %s\n", inet_ntoa(ih->SrcAdd) );
        printf("Dst IP  : %s\n", inet_ntoa(ih->DstAdd) );

}

void PrintTCPHeader(const u_char *packet){
    TCPH *th;
    th = (TCPH *)packet;
    printf("======== TCP Heather ========\n");
    printf("Src Port : %d\n", ntohs(th ->SrcPort));
    printf("Dst Port : %d\n", ntohs(th -> DstPort));
}

void PrintHttpHeader(const uint8_t *packet){
    HttpH *hh;
    hh = (HttpH *)packet;
    printf("======== Http Heather ========\n");
    for(int i =0; i<16; i++) {
        printf("%02x ",hh -> HTP[i]);
    }
    printf("\n");
}


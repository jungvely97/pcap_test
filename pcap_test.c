#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

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
     const char HTP[ ];
}HttpH;

void PrintEthernetHeader(const u_char *packet);
void PrintIPHeader(const u_char *packet);
void PrintTCPHeader(const u_char *packet);
void PrintHttpHeader(const uint8_t *packet);

void help(){
    printf("Write Interface Name\n");
    printf("Sample : pcap_test ens33\n");
}

u_int len;

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
    TCPH *tcp_off;
    u_int length;
    pcap_t* handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);
    if (handle == NULL){
        printf("%s : %s \n", dev, errbuf);
        exit(1);
    }

    while(1){

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) exit(1);
        packet += 14;
        tlen = (IPH *)packet;
        tcp_off = (TCPH *)packet;
        length = htons(tlen->TotalLen) - (uint16_t)(tlen->IHL)*4 -htons(tcp_off->Offset);
        packet +=(uint16_t)(tlen->IHL)*4;
        packet += (u_char)length;
        len = length;
        PrintHttpHeader(packet);
    }

    pcap_close(handle);
    return 0;
}

void PrintHttpHeader(const uint8_t *packet){
    HttpH *hh;
    hh = (HttpH *)packet;
    const char gilgil[23] = {0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x67, 0x69, 0x6c, 0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a};

    //for(i =0; i< len; i++) if( memcmp(hh->HTP[i], gilgil, 24) == 0) printf("Bad site\n");
//    for(int i =0; i<16; i++) {
//        printf("%02x  ",hh -> HTP[i]);
//    }
//    printf("\n");

//    for(int i =0; i< len; i++) {
//        if( memcmp(((const void*)hh->HTP[i], (const void*)gilgil[i], 1) == 0 )&& (memcmp((const void*)hh->HTP[i+1], (const void)gilgil[i+1], 1) == 0 )&&
//            memcmp(hh->HTP[i+2], gilgil[i+2], 1) == 0 && memcmp(hh->HTP[i+3], gilgil[i+3], 1) == 0 &&
//            memcmp(hh->HTP[i+4], gilgil[i+4], 1) == 0 && memcmp(hh->HTP[i+5], gilgil[i+5], 1) == 0 &&
//            memcmp(hh->HTP[i+6], gilgil[i+6], 1) == 0 && memcmp(hh->HTP[i+7], gilgil[i+7], 1) == 0 &&
//            memcmp(hh->HTP[i+8], gilgil[i+8], 1) == 0 && memcmp(hh->HTP[i+9], gilgil[i+9], 1) == 0 &&
//            memcmp(hh->HTP[i+10], gilgil[i+10], 1) == 0 && memcmp(hh->HTP[i+11], gilgil[i+11], 1) == 0 &&
//            memcmp(hh->HTP[i+12], gilgil[i+12], 1) == 0 && memcmp(hh->HTP[i+13], gilgil[i+13], 1) == 0 &&
//            memcmp(hh->HTP[i+14], gilgil[i+14], 1) == 0 && memcmp(hh->HTP[i+15], gilgil[i+15], 1) == 0 &&
//            memcmp(hh->HTP[i+16], gilgil[i+16], 1) == 0 && memcmp(hh->HTP[i+17], gilgil[i+17], 1) == 0 &&
//            memcmp(hh->HTP[i+18], gilgil[i+18], 1) == 0 && memcmp(hh->HTP[i+19], gilgil[i+19], 1) == 0 &&
//            memcmp(hh->HTP[i+20], gilgil[i+20], 1) == 0 && memcmp(hh->HTP[i+21], gilgil[i+21], 1) == 0 &&
//            memcmp(hh->HTP[i+22], gilgil[i+22], 1) == 0)printf("Bad site\n");
//    }
   if( strcmp(hh->HTP, gilgil) == 0)
   {
       printf("======== Http Heather ========\n");
       printf("Bad site\n");
   }


}


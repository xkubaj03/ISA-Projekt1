/*
 *  VUT FIT Generování NetFlow dat ze zachycené síťové komunikace - Projekt ISA
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#define BUFFER 1024                // buffer length
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include "sys/types.h"

#include<netdb.h>
#include <getopt.h>
#include <cstdlib>

#include <iostream>       // std::cout
#include <pcap/pcap.h>
#define __FAVOR_BSD
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include <net/ethernet.h>
#include <map>
#define FILTER "ip and (udp or tcp or icmp)"
struct my_ip {
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src,ip_dst;	/* source and dest address */
};
struct ftpdu_v5 {
    /* 24 byte header */
    u_int16_t version = htons(5); /* 5 */
    u_int16_t count = htons(1); /* The number of records in the PDU */
    u_int32_t sysUpTime = 0; /* Current time in millisecs since router booted */
    u_int32_t unix_secs; /* Current seconds since 0000 UTC 1970 */
    u_int32_t unix_nsecs; /* Residual nanoseconds since 0000 UTC 1970 */
    u_int32_t flow_sequence = 0; /* Seq counter of total flows seen */
    u_int8_t engine_type = 0; /* Type of flow switching engine (RP,VIP,etc.) */
    u_int8_t engine_id = 0; /* Slot number of the flow switching engine */
    u_int16_t reserved =  htons(0);
    /* 48 byte payload */
};
struct ftrec_v5 {
    u_int32_t srcaddr; /* Source IP Address */
    u_int32_t dstaddr; /* Destination IP Address */
    u_int32_t nexthop = htonl(0); /* Next hop router's IP Address */
    u_int16_t input =  htons(0); /* Input interface index */
    u_int16_t output =  htons(0); /* Output interface index */
    u_int32_t dPkts = 1; /* Packets sent in Duration */
    u_int32_t dOctets; /* Octets sent in Duration. *///velikost hlaviček
    u_int32_t First; /* SysUptime at start of flow */
    u_int32_t Last; /* and of last packet of flow */
    u_int16_t srcport; /* TCP/UDP source port number or equivalent */
    u_int16_t dstport; /* TCP/UDP destination port number or equiv */
    u_int8_t pad = 0;
    u_int8_t tcp_flags = 0; /* Cumulative OR of tcp flags */
    u_int8_t prot; /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
    u_int8_t tos; /* IP Type-of-Service */
    u_int16_t src_as =  htons(0); /* originating AS of source address */
    u_int16_t dst_as =  htons(0); /* originating AS of destination address */
    u_int8_t src_mask = 0; /* source address prefix mask bits */
    u_int8_t dst_mask = 0; /* destination address prefix mask bits */
    u_int16_t drops =  htons(0);
};
struct Packet {
    ftpdu_v5 header;
    ftrec_v5 body;
};
static std::map<std::tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t, u_int8_t>, Packet> MojeMapa;
std::tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t, u_int8_t> MyKey;
/* Source / Destination IP Address *//* TCP/UDP source /destination port number or equivalent */ // Prot, tos

static struct Packet MyPacket;
struct Packet EmptyPacket;

int activeN = 0;
int inactiveN = 0;
int Mnum = 0;
int FlowSeqence = 0;

int sock; // socket descriptor
char buffer[BUFFER];

u_int32_t FIRST_packet = 0;

u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Zpracuje ip hlavičku
     * */
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */
    /* check version */
    if(version != 4)
    {
        fprintf(stdout,"Unknown version %d\n",version);
        return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        std::get<0>(MyKey) = ip->ip_src.s_addr;
        std::get<1>(MyKey) = ip->ip_dst.s_addr;
        MyPacket.body.srcaddr = ip->ip_src.s_addr;
        MyPacket.body.dstaddr = ip->ip_dst.s_addr;
    }
    std::get<5>(MyKey) = ip->ip_tos;
    MyPacket.body.tos = ip->ip_tos;
    if(ip->ip_p == 6) //6 je TCP
    {
        const struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
        std::get<2>(MyKey) = ((struct tcphdr*)tcp)->th_sport;
        std::get<3>(MyKey) = tcp->th_dport;
        std::get<4>(MyKey) = 6;
        MyPacket.body.prot = 6;
        MyPacket.body.srcport = tcp->th_sport;
        MyPacket.body.dstport = tcp->th_dport;
        MyPacket.body.tcp_flags = tcp->th_flags;
    }else if(ip->ip_p == 17) //UDP
    {
        const struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
        std::get<2>(MyKey) = udp->uh_sport;
        std::get<3>(MyKey) = udp->uh_dport;
        std::get<4>(MyKey) = 17;
        MyPacket.body.prot = 17; //udp
        MyPacket.body.srcport = udp->uh_sport;
        MyPacket.body.dstport = udp->uh_dport;
    }else if(ip->ip_p == 1) //ICMP
    {
        //Nemá porty k vypsání
        std::get<4>(MyKey) = 1;
        MyPacket.body.prot = 1; //icmp
    }
    return NULL;
}
int NumOrEnd (const std::string& str){
    if(std::stoi (str)) return std::stoi (str);
    else {
        fprintf(stderr, "Převod čísla: \"%s\" selhal\n", str.c_str());
        exit(2);
    }
}
u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Zpracuje ethernetovou hlavičku
     * */
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDR_LEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);
    /* Lets print SOURCE DEST TYPE LENGTH */
    time_t rawtime = pkthdr->ts.tv_sec;
    /* https://www.epochconverter.com/programming/c
     * Práce s časem v c
     * */
    struct tm  ts;
    char buf[80];
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts);
    if(FIRST_packet == 0) FIRST_packet = ((pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000));
    MyPacket.header.sysUpTime = ((pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000) - FIRST_packet);
    MyPacket.body.First = MyPacket.header.sysUpTime;
    MyPacket.body.Last = MyPacket.header.sysUpTime;
    MyPacket.header.unix_secs = pkthdr->ts.tv_sec;
    MyPacket.header.unix_nsecs = pkthdr->ts.tv_usec * 1000;
    return ether_type;
}
int CountMap = 0;
u_int32_t NumberOfSendFlows = 0;
void SendAndRemoveByKey(std::tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t, u_int8_t> SendThisKey){
    //fprintf(stdout, "Odesilam %d", NumberOfSendFlows);
    if(MojeMapa.find(SendThisKey) == MojeMapa.end()){
        fprintf(stderr, "Byl odeslan neexistujici klic\n");
        return;
    }
    int i;
    //Network byte order
    MojeMapa.find(SendThisKey)->second.header.flow_sequence = htonl(NumberOfSendFlows);
    MojeMapa.find(SendThisKey)->second.body.dPkts = htonl(MojeMapa.find(SendThisKey)->second.body.dPkts);
    MojeMapa.find(SendThisKey)->second.body.dOctets = htonl(MojeMapa.find(SendThisKey)->second.body.dOctets);
    MojeMapa.find(SendThisKey)->second.body.First = htonl(MojeMapa.find(SendThisKey)->second.body.First);
    MojeMapa.find(SendThisKey)->second.body.Last = htonl(MojeMapa.find(SendThisKey)->second.body.Last);
    MojeMapa.find(SendThisKey)->second.header.unix_secs = htonl(MojeMapa.find(SendThisKey)->second.header.unix_secs);
    MojeMapa.find(SendThisKey)->second.header.unix_nsecs = htonl(MojeMapa.find(SendThisKey)->second.header.unix_nsecs);
    MojeMapa.find(SendThisKey)->second.header.sysUpTime = htonl(MojeMapa.find(SendThisKey)->second.header.sysUpTime);


    //Send flow (Inspirováno UDPclient2)
    memcpy(&buffer, &MojeMapa.find(SendThisKey)->second, sizeof (Packet));
    i = send(sock,buffer,sizeof(Packet),0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
    {
        fprintf(stderr, "send() failed\n");
    }
    else if (i != sizeof (Packet))
        fprintf(stderr, "send(): buffer written partially\n");
    //Delete flow
    MojeMapa.erase(SendThisKey);
    NumberOfSendFlows++;
    //fprintf(stdout, " -- Odeslano\n");
}
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    /* http://yuba.stanford.edu/~casado/pcap/disect2.c
     * Autor Martin Casado 2001-Jun-24
     * Inspiroval jsem se s postupem zpracování
     * */
    MyPacket = EmptyPacket;
    CountMap = 0;

    MyPacket.body.dOctets = pkthdr->len - ETH_HLEN;


    u_int16_t type = handle_ethernet(args,pkthdr,packet);
    if(type == ETHERTYPE_IP)
    {/* handle IP packet */
        handle_IP(args,pkthdr,packet);
    }else {
        fprintf(stderr, "Přišel špatný packet\n");
    }

    //Kontrola timerů
    auto iterator = MojeMapa.begin();
    while(iterator != MojeMapa.end()){
        if((MyPacket.body.First - iterator->second.body.First) > (1000 * activeN)){
            //Vypršel čas active
            SendAndRemoveByKey((iterator++)->first);
        } else if((MyPacket.body.Last - iterator->second.body.Last) > (1000 * inactiveN)){
            //Vypršel čas inactive
            SendAndRemoveByKey((iterator++)->first);
        }else {
            CountMap++;
            iterator++;
        }
    }

    //Uložení/připsání do flow
    if(MojeMapa.find(MyKey) != MojeMapa.end()) {
        //Nalezeno
        MojeMapa[MyKey].body.dPkts++;
        MojeMapa[MyKey].body.dOctets += MyPacket.body.dOctets;
        MojeMapa[MyKey].body.Last = MyPacket.body.Last;
        MojeMapa[MyKey].body.tcp_flags = MojeMapa[MyKey].body.tcp_flags | MyPacket.body.tcp_flags;
        //tcp flag & TH_FIN || tcp flag & TH_RST
        if(MojeMapa[MyKey].body.tcp_flags & TH_FIN || MojeMapa[MyKey].body.tcp_flags & TH_RST)
        {
            //Flag fin nebo rst
            SendAndRemoveByKey(MyKey);
        }
    } else{
        //Přidání flow
        MojeMapa[MyKey] = MyPacket;
        if(MojeMapa[MyKey].body.tcp_flags & TH_FIN || MojeMapa[MyKey].body.tcp_flags & TH_RST)
        {
            //Flag fin nebo rst
            SendAndRemoveByKey(MyKey);
        }
    }
    //Pokud je v mapě moc flowů odešlu nejstarší
    if((Mnum <= MojeMapa.size())){
        bool first = 1;
        u_int32_t Oldest = 0;
        std::tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t, u_int8_t> OldestKey;
        auto iterator = MojeMapa.begin();
        while (iterator != MojeMapa.end()){
            if(first){
                first = 0;
                Oldest = iterator->second.body.First;
                OldestKey = iterator->first;
            }
            else if(Oldest > iterator->second.body.First) {
                Oldest = iterator->second.body.First;
                OldestKey = iterator->first;
            }
            iterator++;
        }
        SendAndRemoveByKey(OldestKey);
    }

}
int main(int argc, char* argv[]) {
    /* https://www.man7.org/linux/man-pages/man3/getopt.3.html
     * Author Michael Kerrisk 2021-08-27
     * Načtení a zpracování argumentů
     * */

    int opt;

    std::string file;
    std::string NetFlowCollector;
    std::string active;
    std::string inactive;
    std::string M;

    while ((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
        switch (opt) {
            case 'f':
                file = optarg;
                break;
            case 'c':
                NetFlowCollector = optarg;
                break;
            case 'a':
                active = optarg;
                break;
            case 'i':
                inactive = optarg;
                break;
            case 'm':
                M = optarg;
                break;
            default:
                fprintf(stderr,
                        "./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
                exit(EXIT_FAILURE);
        }
    }
    {
        if (file.empty()) file = "-";
        if (NetFlowCollector.empty()) NetFlowCollector = "127.0.0.1:2055";
        if (active.empty()) active = "60";
        if (inactive.empty()) inactive = "10";
        if (M.empty()) M = "1024";

    }


        activeN = 0;
        inactiveN = 0;
        Mnum = 0;

        std::string address;
        int port;
        struct hostent *AddrInfo;
        activeN = NumOrEnd(active);
        inactiveN = NumOrEnd(inactive);
        Mnum = NumOrEnd(M);

        address = NetFlowCollector.substr(0, NetFlowCollector.find_last_of(':'));

        std::string StringPort = NetFlowCollector.substr(NetFlowCollector.find_last_of(':') + 1);
        if(StringPort.empty() || StringPort == address) port = 2055;
        else port = NumOrEnd(StringPort);


    // UDP odesilani (UDP client2)
    //int sock;                        // socket descriptor
    //char buffer[BUFFER];
    //int msg_size, i;
    struct sockaddr_in server, from; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    //socklen_t len, fromlen;

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;
    // make DNS resolution of the first parameter using gethostbyname()
    if ((servent = gethostbyname(address.c_str())) == NULL){
        fprintf(stderr, "Převod hostname: \"%s\" selhal\n", address.c_str());
        exit(2);
    }
    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    server.sin_port = htons(port);        // server port (network byte order)

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        fprintf(stderr, "socket() failed\n");
    //printf("* Server socket created\n");

    //len = sizeof(server);
    //fromlen = sizeof(from);

    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        fprintf(stderr, "connect() failed\n");







    //Otevreni spojeni
    pcap_t *handle;            /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program fp;        /* The compiled filter */

    handle = pcap_open_offline(file.c_str(), errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open %s: %s\n", file.c_str(), errbuf);
        return (2);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, FILTER, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER, pcap_geterr(handle));
        return (2);
    }

    pcap_loop(handle, -1, my_callback, nullptr);
    pcap_close(handle);

    //Odešlu zbylé packety
    auto iterator = MojeMapa.begin();
    while(iterator != MojeMapa.end()){
        SendAndRemoveByKey((iterator++)->first);
    }

    close(sock);
    return 0;
}
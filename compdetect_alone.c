#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include "cJSON.h"

#define IP4_HDRLEN 20  // IPv4 header legnth
#define TCP_HDRLEN 20 // TCP header lenght, does not include data
#define SIZE_ETHERNET 14 // ethernet header size

/* snap legnth (max bytes per packets to capture) */
#define SNAP_LEN 1518

typedef struct
{
	char server_ip[100];
	char client_ip[100];
	int sourceUDP_port;
	int destinationUDP_port;
	int port_sinHead;
	int port_sinTail;
	int port_TCP;
	int payload_size;
	int measure_time;
	int num_of_paks;
	int timeTL;
}instructions;

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* what type of info received  IP? ARP? RARP? etc */
};

/* Packet sniffer pseudo-IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
  	u_short ip_len;                 /* total length */
  	u_short ip_id;                  /* identification */
  	u_short ip_off;                 /* fragment offset field */
  	#define IP_RF 0x8000            /* reserved fragment flag */
  	#define IP_DF 0x4000            /* don't fragment flag */
  	#define IP_MF 0x2000            /* more fragments flag */
  	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  	u_char  ip_ttl;                 /* time to live */
  	u_char  ip_p;                   /* protocol */
  	u_short ip_sum;                 /* checksum */
  	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Packet sniffer pseudo-TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
  	u_short th_dport;               /* destination port */
  	tcp_seq th_seq;                 /* sequence number */
  	tcp_seq th_ack;                 /* acknowledgement number */
  	u_char  th_offx2;               /* data offset, rsvd */
  	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  	u_char  th_flags;
  	#define TH_FIN  0x01
  	#define TH_SYN  0x02
  	#define TH_RST  0x04
  	#define TH_PUSH 0x08
  	#define TH_ACK  0x10
  	#define TH_URG  0x20
  	#define TH_ECE  0x40
  	#define TH_CWR  0x80
  	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  	u_short th_win;                 /* window */
  	u_short th_sum;                 /* checksum */
  	u_short th_urp;                 /* urgent pointer */
};

//Global Variables
clock_t low_start, low_end, high_start, high_end; //Timers for TCP measuring
pcap_t *handle;       /* packet capture handle */


//handles timeout in receiving packets
//and ends packet sniffing 
void alarm_handler(int sig){
  	pcap_breakloop(handle);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

  	static int count = 1;                   /* packet counter */
  
 	/* declare pointers to packet headers */
 	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  	const struct sniff_ip *ip;              /* The IP header */
  	const struct sniff_tcp *tcp;            /* The TCP header */

  	int size_ip;
  	int size_tcp;
  
  	count++;
  
  	/* define ethernet header */
  	ethernet = (struct sniff_ethernet*)(packet);
  
  	/* define/compute ip header offset */
  	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  	size_ip = IP_HL(ip)*4;
  	if (size_ip < 20) {
	       	printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
  	}
  
  	/* define/compute tcp header offset */
  	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  	size_tcp = TH_OFF(tcp)*4;
  	if (size_tcp < 20) {
	       	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
  
  	int src_port = ntohs(tcp->th_sport);
  	int dst_port = ntohs(tcp->th_dport);

  	if(count == 2 && src_port == 8000 && dst_port == 8080){
		low_start = clock();
  	}else if(count == 3 && src_port == 8001 && dst_port == 8080){
		low_end = clock();
  	}else if(count == 4 && src_port == 8000 && dst_port == 8080){
    		high_start = clock();
  	}else if(count == 5 && src_port == 8001 && dst_port == 8080){
   		 high_end = clock();
  	}
	return;
}

// allocate mem for array of chars
char* allocate_strmem(int len){
	void *tmp;

  	if(len <= 0){
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (char *) malloc (len * sizeof (char));
	if(tmp != NULL){
		memset(tmp, 0, len * sizeof (char));
		return (tmp);
	}else{
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of unsigned chars.
uint8_t* allocate_ustrmem(int len){
       	void *tmp;

	if(len <= 0){
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	if(tmp != NULL){
		memset(tmp, 0, len * sizeof (uint8_t));
	       	return (tmp);
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of ints.
int* allocate_intmem(int len){
	void *tmp;

	if(len <= 0){
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (int *) malloc (len * sizeof (int));
	if(tmp != NULL){
		memset(tmp, 0, len * sizeof (int));
		return (tmp);
	} else {
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit(EXIT_FAILURE);
	}
}

//calculates the checksum for the given header
unsigned short checksum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short result;

  	sum=0;
  	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

  	sum = (sum>>16)+(sum & 0xffff);
  	sum = sum + (sum>>16);
  	result=(short)~sum;
  
  	return(result);
}


/*Reads config information from givben config file*/
instructions cJSON_make_struct( char * file, instructions settings){
	cJSON *json, *item, *object;
	json = cJSON_Parse(file);
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip_address");
	if(item== NULL){
		printf("Missing server ip addreess. Please include in config file. Exiting now\n");
		exit(0);
	}else{
		strcpy(settings.server_ip, item->valuestring);
	}

	item =cJSON_GetObjectItemCaseSensitive(json, "client_ip_address");
	if(item== NULL){
		printf("Missing client Ip address in config please include. Now exiting\n");
		exit(0);
	}else{
		strcpy(settings.client_ip, item->valuestring);
	}
	item = cJSON_GetObjectItemCaseSensitive(json, "sourceport_UDP");
	if(item == NULL){
		printf("Missing source UDP prot in config file. Please include. Now Exiting \n");
		exit(0);
	}else{
		settings.sourceUDP_port=item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "destinationport_UDP");
	if(item == NULL){
		printf("Missing UDP destination port in config file. please include. Exiting now\n");
		exit(0);
	}else{
		settings.destinationUDP_port=item->valueint;
	}

	
	item = cJSON_GetObjectItemCaseSensitive(json, "TCP_Head_Syn");
	if(item==NULL){
		printf("Mising  TCP head Syn x port in config file. Please include Head port\nExiting now\n");
		exit(0);
	}else{
		settings.port_sinHead= item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "TCP_Tail_Syn");
	if(item == NULL){
		printf("Missing TCP tail Syn y port in config file. Please include it. Exiting now\n");
		exit(0);
	}else{
		settings.port_sinTail= item->valueint;
	}
	
	item = cJSON_GetObjectItemCaseSensitive(json, "port_TCP");
	if(item == NULL){
		printf(" No regular TCP port, but can still continue.\n");
	}else{
		settings.port_TCP= item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "payload_sizeUDP");
	if(item== NULL){
		settings.payload_size = 1000;
        }else{
		settings.payload_size= item->valueint;
	}



	item = cJSON_GetObjectItemCaseSensitive(json, "measure_time");
	if(item== NULL){
		settings.measure_time= 15;
        }else{
		settings.measure_time= item->valueint;
	}


	item = cJSON_GetObjectItemCaseSensitive(json, "number_of_packets");
	if(item== NULL){
		settings.num_of_paks= 6000;
	}else{
		settings.num_of_paks= item->valueint;
	}


	item= cJSON_GetObjectItemCaseSensitive(json, "ttl");
	if(item == NULL){
		settings.timeTL= 255;
	}else{
		settings.timeTL= item->valueint;
	}
	cJSON_Delete(json);

	return settings;
}

size_t get_file_size(const char *filepath){
	if(filepath == NULL){
		return 0;
	}
	struct stat filestat;
	memset(&filestat, 0, sizeof(struct stat));

	if(stat(filepath, &filestat) == 0){
		return filestat.st_size;
	}else{
		return 0;
	}
}


instructions  read_file(char *filename){
	FILE *fp;
	instructions config;
	/*get file size*/
	size_t size = get_file_size(filename);
	if(size==0){
		printf("failed to get file size\n");
	}

	char * bufr = malloc(size+1);
	if(bufr == NULL){
		printf("Malloc failed\n");
	}

	memset(bufr, 0, size+1);
	fp=fopen(filename, "rb");

	fread(bufr, 1, size, fp);

	fclose(fp);

	config = cJSON_make_struct(bufr, config);
	free(bufr);

	return config;

	printf("reading file complete\n");
}

int main(int argc, char *argv[]){
	printf("Getting Config information\n");
	if(argc !=2){
		printf("Missing config file information");
		exit(1);
	}
	instructions config = read_file(argv[1]);

	// variables read from config file
	char * serverip= config.server_ip;
	char * clientip= config.client_ip;
	int udp_source_port= config.sourceUDP_port;
	int udp_dest_port= config.destinationUDP_port;
	int tcp_sinHead= config.port_sinHead;
	int tcp_sinTail= config.port_sinTail;
	int probe_tcp = config.port_TCP;
	int payload= config.payload_size;
	int inter_measure_time= config.measure_time;
	int number_of_packets= config.num_of_paks;
	int timeToLive= config.timeTL;


	struct udpPacket{
		int length;
		char bytes[payload];
	};

	//Creating TCP SYN packets
	
	//Declaring varibles to be used in Raw scoket 
  	int status, datalen, sd, *ip_flags;
  	char *interface, *target, *src_ip, *dst_ip;
  	struct ip iphdr;
  	struct tcphdr tcphdr;
  	uint8_t *data, *src_mac, *dst_mac;
  	struct addrinfo hints, *res;
  	struct sockaddr_in *ipv4;
  	struct sockaddr_ll device;
  	struct ifreq ifr;
  	void *tmp;


	//Allocate memory for variables
	// Allocate memory for various arrays.
 	src_mac = allocate_ustrmem(6);
 	dst_mac = allocate_ustrmem(6);
 	data = allocate_ustrmem(IP_MAXPACKET);
 	interface = allocate_strmem(40);
 	target = allocate_strmem(40);
 	src_ip = allocate_strmem(INET_ADDRSTRLEN);
 	dst_ip = allocate_strmem(INET_ADDRSTRLEN);
 	ip_flags = allocate_intmem(4);

	low_start, low_end, high_start, high_end = 0;

	int time = inter_measure_time;

	 //Interface to send packets 
	strcpy(interface, "enp0s3");

	 //Now Setting up packet sniffing
	char errbuf[PCAP_ERRBUF_SIZE];    /* error buffer for pcap */

	 //Filter for recieving tcp packets from server with rst set
	char filter_exp[] = "(tcp port (8080 or 8000 or 8001)) and (tcp[tcpflags] & (tcp-rst) == (tcp-rst))";   /* filter expression [3] */
	struct bpf_program fp;      /* compiled filter program (expression) */
	bpf_u_int32 mask;     /* subnet mask */
	bpf_u_int32 net;      /* ip */
	int num_packets = 4;      /* number of packets to capture */

	 /* get network number and mask associated with capture device */
	if(pcap_lookupnet(interface, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
		net = 0;
		mask = 0;
	 }

	 //Open Capturing device
	 handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
	if(handle == NULL){
		 fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
		 exit(EXIT_FAILURE);
	}
	/* Ensure we are capturing on a ethernet device */
	if(pcap_datalink(handle) != DLT_EN10MB) {
	 	fprintf(stderr, "%s is not an ethernet\n", interface);
		exit(EXIT_FAILURE);
	}
	
	//Compiling filter expression
	if(pcap_compile(handle, &fp, filter_exp, 0, net) ==-1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// Applying compiled filter
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// creating raw socket to look up interface
	if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("Failed to get socket descriptio for ioctl()\n");
		exit(EXIT_FAILURE);
	}

	// Use ioctl() to find interface name and get MAC addr
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name,sizeof(ifr.ifr_name), "%s", interface);
	if(ioctl(sd, SIOCGIFHWADDR, &ifr) < 0){
		perror("ioctl() failed to get source MAC address\n");
		exit(EXIT_FAILURE);
	}

	close(sd);

	//copy source Mac address
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

	// Find itnerface index from interface name and store index in
	// struct sockaddr_ll device is used for sendto()
	memset(&device, 0, sizeof(device));
	if((device.sll_ifindex = if_nametoindex(interface)) == 0){
		perror("if_nametoindex() failed to get interface index\n");
		exit(EXIT_FAILURE);
	}
	// Seetting Destination MAC addr
	// This is Mac address of vm bridge adapter settings i.e. vm connection
	dst_mac[0] = 0x08;	
	dst_mac[1] = 0x00;	
	dst_mac[2] = 0x27;	
	dst_mac[3] = 0x1f;	
	dst_mac[4] = 0xc6;	
	dst_mac[5] = 0xb3;	
	//May need to change
	//b0:b9:8a:77:33:5a
	//or 08:00:27:1f:c6:b3
	
	//Source ipv4 addr
	strcpy(src_ip, config.client_ip);

	//Destiantion Ipv4 addr
	strcpy(target, config.server_ip);
	// fill out hints for getaddrinfo()
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;
	
	//check if getaddrinfo got address correctly
	if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0){
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if(inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL){
		status = errno;
		fprintf(stderr, "inet_ntop failed \n Error Message: %s\n", strerror(status));
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res);

	//fill out sockaddr_ll
	device.sll_family= AF_INET;
	device.sll_protocol = htons(ETH_P_IP);
	memcpy(device.sll_addr, dst_mac, 6);

	datalen = 5;
	data[0] = 'H';
	data[1] = 'e';
	data[2] = 'a';
	data[3] = 'd';
	data[4] = '1';

	// TODO POTENTIALLY ADD PACKET SNIFFING FOR RST HERE	
	
	// must create child to process to send udp packets
	// while also sniffing for returning rst packets from server
	
	pid_t child = fork();

	if(child == 0){
		alarm(inter_measure_time+5);
		signal(SIGALRM, alarm_handler);

		// sniff for incoming packets
		int result = pcap_loop(handle, num_packets,got_packet, NULL);

		pcap_freecode(&fp);
		pcap_close(handle);

		if(result==0){// if expected paks are received
			//calculate time elapsed in seconds
			double total_low = (((double)low_end) - ((double)low_start)) / ((double)CLOCKS_PER_SEC);
			double low_time = total_low*1000; //convert seconds to milliseconds
			double total_high = (((double)high_end) - ((double)high_start)) / ((double)CLOCKS_PER_SEC);
			double high_time = total_high*1000; //convert seconds to milliseconds
			double difference = total_high - total_low;
			
			if(difference <= 100){
				printf("\n No Network COmpression detected.\n");
			}else{
				printf("\n Network COmpression Detected. \n");
			}
		}else if(result ==-2){
			// timout occurs before all packets received
			printf("Failed to detect Network Compression\n");
		}else{
			//Any otehr error occured
			printf("Pcpap Error occured\n");
		}
		//end the child
		exit(0);
	}
	//create ipv4 header 
	
	//IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

	//IP version 
	iphdr.ip_v = 4;

	//type of service
	iphdr.ip_tos = 0;

	// Total length of datagram (16 bits) = Ip hdr + tcp hdr + datalen
	iphdr.ip_len = (IP4_HDRLEN + TCP_HDRLEN + datalen);

	// ID Sequence number
	iphdr.ip_id = htons (0);

	// FLags, and frag offset 
	ip_flags[0] = 0;

	//Dont frag flag
	ip_flags[1] = 0;

	//more frags flowwoing flag
	ip_flags[2] = 0;

	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);
	//setting ttl from config informatiom
	iphdr.ip_ttl = timeToLive;

	// Transport layer protocol
	iphdr.ip_p = IPPROTO_TCP;
	
	//Source IPv4 address
	if((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_src))) !=1){
		fprintf(stderr, "inet_pton failed. \n Error message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	//Destination IPv4 address
	if((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) !=1){
		fprintf (stderr, "inet_pton failed.\nError message: %s", strerror (status));
    exit(EXIT_FAILURE);
	}

	// ipv4 header checksum, init to 0
	iphdr.ip_sum = 0;

	//create and populate datagram buffer
	char datagram[4096];
	memset(datagram, 0, 4096);

	memcpy(datagram, &iphdr, sizeof(struct iphdr));
	memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), data, strlen(data));

	//calculate tcp checksum for ip header
	iphdr.ip_sum = checksum((unsigned short* ) datagram, iphdr.ip_len);

	//TCP header
	memset(&tcphdr, 0, sizeof(tcphdr));

	tcphdr.th_sport = htons(htons(probe_tcp)); // set source port
	
	tcphdr.th_dport = htons(tcp_sinHead);

	tcphdr.th_seq = htonl(0); //sequence # is 0 because first packet
	
	tcphdr.th_ack = htonl(0); //ack # also 0 because first packet
	
	tcphdr.th_off = 5; //set the tcp header offset
	
	int* tcp_flags = allocate_intmem(6); // allocate mem for 8 tcp flags
	tcphdr.th_flags = 0; //set initial tchdhr flags
	tcphdr.th_flags += TH_SYN; //set the SYN flag to 1
	
	tcphdr.th_win = htons(5840); //set tcp window size
	tcphdr.th_sum = 0; //set checksum later
	tcphdr.th_urp = htons(0); //set urgent pointer not used
	
	//create pseudoheader and pseudogram for tcp checksum calculation
	char* pseudogram;
	struct pseudo_header psh;

	//populate pseudo ip header
	psh.source_address = inet_addr(clientip); // may need to change
	psh.dest_address = ipv4->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	//allocate memory for pseudogram
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);

	//copy data into pseudogram
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr , sizeof(struct tcphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data , strlen(data));

	//calculate tcp check sum
	tcphdr.th_sum = checksum((unsigned short*) pseudogram , psize);

	//frame length
	int tcp_packet_length = IP4_HDRLEN + TCP_HDRLEN + datalen;

	int s; // scoket file descriptor used for sending tcp packets
	
	if((s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
    		exit(1);
	}

	// set socket option to include ip header
	int flag = 1;
	if(setsockopt (s, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag)) < 0){

		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy tcp header information into datagram
	memcpy(datagram + sizeof(struct iphdr) , &tcphdr, sizeof(struct tcphdr));

	if(sendto (s, datagram, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
		exit(1);
	}

	close(s);



	//Creating UDP connection to send Packets
	int sockUDP;

	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create UDP socket\n");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in serveraddr, clientaddr;
	
	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(udp_dest_port);
	serveraddr.sin_addr.s_addr= inet_addr(serverip);

	clientaddr.sin_family = AF_INET;
	clientaddr.sin_port = htons(udp_source_port);
	clientaddr.sin_addr.s_addr = inet_addr(clientip);

	if(bind(sockUDP, (struct sockaddr *) &clientaddr, sizeof(clientaddr)) <0){
		perror("Unable to Bind to UDP socket");
		exit(EXIT_FAILURE);
	}

	struct udpPacket *low_entropy = (struct udpPacket *) malloc (number_of_packets * sizeof(struct udpPacket));
	struct udpPacket *high_entropy = (struct udpPacket *) malloc (number_of_packets * sizeof(struct udpPacket));

	//creating low entropy packets
	unsigned short id=0;
	for( int i=0; i<number_of_packets; i++){
		low_entropy[i].length = payload;
		for( int j=0; j<(payload -2); j++){
			low_entropy[i].bytes[j]= 0; 
		}

		char packid[2];
		packid[0]=id%256;
		packid[1]=id/256;
		id++;

		char * packetpayload = (char *) malloc(strlen(low_entropy[i].bytes)+ strlen(packid)+1);
		strcpy(packetpayload, packid);
		strcat(packetpayload, low_entropy[i].bytes);
		strcpy(low_entropy[i].bytes, packetpayload);
	}

	unsigned char rngRandomData[payload];
	unsigned int rngData = open("rng", O_RDONLY);
	read(rngData, rngRandomData, payload);
	close(rngData);

	id=0;
	for(int i=0; i<number_of_packets; i++){
		high_entropy[i].length = payload;
		for(int j=0; j< (payload-2); j++){
			high_entropy[i].bytes[j]=rngRandomData[j];
		}

		char packid[2];
		packid[0]=id%256;
		packid[1]=id/256;
		id++;

		char * packetpayload = (char *) malloc(strlen(high_entropy[i].bytes)+ strlen(packid) + 1);
		strcpy(packetpayload, packid);
		strcat(packetpayload, high_entropy[i].bytes);
		strcpy(high_entropy[i].bytes, packetpayload);
	}

	int frag = IP_PMTUDISC_DO;

	if( setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &frag, sizeof(frag)) <0){
		printf("Could not set do not fragment of packets ending now\n");
		exit(1);
	}

	//setting TTL of packets
	if( setsockopt(sockUDP, IPPROTO_IP, IP_TTL, &timeToLive, sizeof(timeToLive)) <0){
		printf("Not able to set ttl of UDP packets. Ending now \n");
		exit(1);
	}

	// now sending low packets
	printf("now sending low packets\n");
	for(int i =0; i< number_of_packets; i++){
		sendto(sockUDP, low_entropy[i].bytes, sizeof(low_entropy[i].bytes), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));
	}
	printf("Lows packets Sent\n");

	//creating tail TCP
	
	//clearing out old data
	memset(data, 0, IP_MAXPACKET);

	//update data to be tail
	data[0] = 'T';
       	data[1] = 'a';
	data[2] = 'i';
	data[3] = 'l';
	data[4] = '1';

	struct ip iphdr_2; //create second ip packet header
	//copy data from first ip header, overwrite necessary information
	memcpy(&iphdr_2, &iphdr, sizeof(struct ip));

	// IPv4 header checksum, initialize to 0
	iphdr_2.ip_sum = 0;
	//create and populate datagram buffer
	char datagram_2[4096];
	memset(datagram_2, 0, 4096);

	memcpy(datagram_2, &iphdr_2, sizeof(struct ip));
	memcpy(datagram_2 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));

	// calculate checksum for ip header
	iphdr_2.ip_sum = checksum((unsigned short* ) datagram_2, iphdr_2.ip_len);

	//create second tcp header copied from the first one
	//overwrite relevant information
	
	struct tcphdr tcphdr_2;
	memcpy(&tcphdr_2, &tcphdr, sizeof(struct tcphdr));

	tcphdr_2.th_dport = htons(tcp_sinTail); //set tail port
	tcphdr_2.th_seq = htonl(1); //sequence # is 1 because second packet
	tcphdr_2.th_sum = 0; //set checksum later
	
	//copy new data into pseudogram buffer
	memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_2 , sizeof(struct tcphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));

	// calc checksum
	tcphdr_2.th_sum = checksum((unsigned short*)pseudogram, psize);
	//create raw tcp socket
	if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include (for ip header)
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy in tcp header information
	memcpy(datagram_2 + sizeof(struct ip) , &tcphdr_2, sizeof(struct tcphdr));

	//send datagram
	if(sendto(s, datagram_2, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
		exit(1);
	}

	close(s);


	printf("Now sleeping\n");
	sleep(inter_measure_time);

	//creatinjg third tcp syn packet
	memset(data, 0, IP_MAXPACKET);

	//update data to be "Head2"
	data[0] = 'H';
	data[1] = 'e';
	data[2] = 'a';
	data[3] = 'd';
	data[4] = '2';

	struct ip iphdr_3; //create third tcp packet header
	memcpy(&iphdr_3, &iphdr, sizeof(struct ip)); //copy data from first ip header
	
	// IPV4 header checksum, init to 0
	iphdr_3.ip_sum = 0;

	//create and populate datagram buffer
	char datagram_3[4096];
	memset(datagram_3, 0, 4096);

	memcpy(datagram_3, &iphdr_3, sizeof(struct ip));
	memcpy(datagram_3 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));

	// calc check sum for ip header
	iphdr_3.ip_sum = checksum((unsigned short* ) datagram_3, iphdr_3.ip_len);

	//create third tcp header copied from the first one
	struct tcphdr tcphdr_3;
	memcpy(&tcphdr_3, &tcphdr, sizeof(struct tcphdr));

	tcphdr_3.th_seq = htonl(2); //sequence # is 2 because third packet
	
	tcphdr_3.th_dport = htons(tcp_sinHead);

	tcphdr_3.th_sum = 0; //initialize checksum to 0
	
	//copy new data into pseudogram
	memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_3 , sizeof(struct tcphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));

	// calc check tcp check sum
	tcphdr_3.th_sum = checksum((unsigned short*)pseudogram, psize);

	// create raw sock
	if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
	       	perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include for ip hdr
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy in tcp header information
	memcpy(datagram_3 + sizeof(struct ip) , &tcphdr_3, sizeof(struct tcphdr));

	if(sendto(s, datagram_3, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
	}

	close(s);


	printf("Now sending high data\n");


	for(int i=0; i< number_of_packets; i++){
		sendto(sockUDP, high_entropy[i].bytes, sizeof(high_entropy[i].bytes), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));
	}

	printf("High packet sent\n");

	free(low_entropy);
	free(high_entropy);
	close(sockUDP);

	//clear out old data
	memset(data, 0, IP_MAXPACKET);

	//update data to be "Tail2"
	data[0] = 'T';
	data[1] = 'a';
	data[2] = 'i';
	data[3] = 'l';
  	data[4] = '2';

	struct ip iphdr_4; //create fourth tcp packet header
	memcpy(&iphdr_4, &iphdr, sizeof(struct ip)); //copy data from first ip header
	
	//ipv4 header check sum init to 0
	iphdr_4.ip_sum = 0;

	//create and populate dgram buffr
	char datagram_4[4096];
	memset(datagram_4, 0, 4096);

	memcpy(datagram_4, &iphdr_4, sizeof(struct ip));
	memcpy(datagram_4 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));
	//calculate checksum for ip header
	iphdr_4.ip_sum = checksum((unsigned short* ) datagram_4, iphdr_4.ip_len);


	//create fourth tcp header copied from the first one
	struct tcphdr tcphdr_4;
	memcpy(&tcphdr_4, &tcphdr, sizeof(struct tcphdr));
	tcphdr_4.th_dport = htons(tcp_sinTail); //set tail syn port
	
	tcphdr_4.th_seq = htonl(3); //sequence # is 3 because fourth packet
	tcphdr_4.th_sum = 0; //set checksum later
	

	//copy new data into pseudogram
	memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_4 , sizeof(struct tcphdr));
  	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));


	//calculate tcp checksum
	tcphdr_4.th_sum = checksum((unsigned short*)pseudogram, psize);

	//create new raw TCP sock
	if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include for ip hdr
	if(setsockopt (s, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}
	//copy in tcp header information
	memcpy(datagram_4 + sizeof(struct ip) , &tcphdr_4, sizeof(struct tcphdr));
	
	// sending tcp tail 2
	if(sendto(s, datagram_4, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0){
		perror("sendto failed");
		exit(1);
	}

	close(s);

	//waiting for rst calculations
	wait(0);

	printf("Standalone has completed\n");

	free(src_mac);
	free(data);
	free(interface);
	free(target);
	free(src_ip);
	free(dst_ip);
	free(ip_flags);
	free(pseudogram);

	return 0;

}

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
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include "cJSON.h"

#define IP4_HDRLEN 20  // IPv4 header legnth
#define TCP_HDRLEN 20 // TCP header lenght, does not include data
#define MAX_PAYLOAD_SIZE 2000



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



//Global Variables
clock_t low_start, low_end, high_start, high_end; //Timers for TCP measuring




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

	struct packet{
		char byte_0_id;
		char byte_1_id;
		char data_payload[MAX_PAYLOAD_SIZE];
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
	// This is Mac address of server wanted to send to 
	dst_mac[0] = 0x08;	
	dst_mac[1] = 0x00;	
	dst_mac[2] = 0x27;	
	dst_mac[3] = 0xad;	
	dst_mac[4] = 0xf9;	
	dst_mac[5] = 0xf2;	
	
	
	//Source ipv4 addr
	strcpy(src_ip, config.client_ip);
	printf("client addr: %s\n", config.client_ip);
	//Destiantion Ipv4 addr
	strcpy(target, config.server_ip);
	printf("server addr: %s\n", config.server_ip);
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

	//more frags following flag
	ip_flags[2] = 0;

	//fragmentation offset 13 bits
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);
	//setting ttl from config informatiom 8 bits
	iphdr.ip_ttl = timeToLive;

	// Transport layer protocol 8bits
	iphdr.ip_p = IPPROTO_TCP;
	
	//Source IPv4 address 32 bits
	if((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) !=1){
		fprintf(stderr, "inet_pton failed. \n Error message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	//Destination IPv4 address 32 bits
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

	tcphdr.th_sport = htons(probe_tcp); // set source port
	
	tcphdr.th_dport = htons(tcp_sinHead); //sser destination port

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

	//frame length = ip header + tcp header +data
	int tcp_packet_length = IP4_HDRLEN + TCP_HDRLEN + datalen;

	int sockRaw; // scoket file descriptor used for sending tcp packets
	
	if((sockRaw = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
    		exit(1);
	}

	// set socket option to include ip header
	int flag = 1;
	if(setsockopt (sockRaw, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag)) < 0){

		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy tcp header information into datagram
	memcpy(datagram + sizeof(struct iphdr) , &tcphdr, sizeof(struct tcphdr));

	if(sendto (sockRaw, datagram, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
		exit(1);
	}

	printf("Sent Sin Head 1\n");
	close(sockRaw);



	//Creating UDP connection to send Packets
	int sockUDP;

	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create UDP socket\n");
		exit(EXIT_FAILURE);
	}

	// set address for udp for the client and server 
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

	//sett do not fragment flag of udp packets
	int frag = IP_PMTUDISC_DO;

	if( setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &frag, sizeof(frag)) <0){
		printf("Could not set do not fragment of packets ending now\n");
		exit(1);
	}

	//setting TTL of udp packets
	if( setsockopt(sockUDP, IPPROTO_IP, IP_TTL, &timeToLive, sizeof(timeToLive)) <0){
		printf("Not able to set ttl of UDP packets. Ending now \n");
		exit(1);
	}

	// now sending low packets
	printf("now sending low packets\n");
	
	char buffer [3000]; // char buffer to send packets through
	
	//creation of low entropy packets
	struct packet *low = (struct packet *) malloc(sizeof(struct packet));
	memset(&low->data_payload, 0, MAX_PAYLOAD_SIZE); // set mem of low packet to all 0


	for(unsigned short int i =0; i< number_of_packets; i++){
		low->byte_0_id= (uint8_t)(i & 0xff); // set lower order byte id
		low->byte_1_id= (uint8_t)(i >> 8); // set higher order byte id
		//copy memory of low packet as char pointer to a string buffer
		memcpy(buffer, (char *) low, sizeof(struct packet));
		// send string buffer but only size of specific payload + 2 to account for id
		sendto(sockUDP, buffer, (payload + 2), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));
		usleep(100); // slep to slow down sending to allow server to receive all packets
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
	if((sockRaw = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include (for ip header)
	if(setsockopt(sockRaw, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy in tcp header information
	memcpy(datagram_2 + sizeof(struct ip) , &tcphdr_2, sizeof(struct tcphdr));

	//send datagram
	if(sendto(sockRaw, datagram_2, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
		exit(1);
	}

	printf("Sent Sin Tail 1\n");

	close(sockRaw);


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
	if((sockRaw = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
	       	perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include for ip hdr
	if(setsockopt(sockRaw, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	//copy in tcp header information
	memcpy(datagram_3 + sizeof(struct ip) , &tcphdr_3, sizeof(struct tcphdr));

	if(sendto(sockRaw, datagram_3, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
		perror("sendto failed");
	}

	printf("Sent Sin Head 2\n");

	close(sockRaw);


	printf("Now sending high data\n");

	//now creating high entropy packet pointer
	struct packet * high= (struct packet *) malloc(sizeof(struct packet));

	// opens up /dev/urandom file called rng and copies data into rngRandomdata
	// to be sued for high entropy data payload
	char rngRandomData2[MAX_PAYLOAD_SIZE];
	unsigned int rngData2 = open("rng", O_RDONLY);
	read(rngData2, rngRandomData2, payload);
	close(rngData2);

	//copy memory of high entropy data into high entropy pack poitner's payload
	memcpy(&high->data_payload, &rngRandomData2, MAX_PAYLOAD_SIZE);

	for(int i=0; i< number_of_packets; i++){
		high->byte_0_id = (uint8_t)(i & 0xff); // set low order byte id
		high->byte_1_id = (uint8_t)(i >> 8); //set higher order byte id
		//copy memory of high entropy packet as char pointer into string buffer
		memcpy(buffer, (char *) high, sizeof(struct packet));
		//send string buffer but only to sie of given payload + 2 to acount for packed id
		sendto(sockUDP, buffer, (payload +2), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));
		usleep(100); //slow down sneding so server can receive all packs
	}

	printf("High packet sent\n");

	free(low);
	free(high);
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
	if((sockRaw = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		perror("Failed to create tcp socket");
		exit(1);
	}

	//set header include for ip hdr
	if(setsockopt(sockRaw, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0){
		perror("Error setting IP_HDRINCL");
		exit(1);
	}
	//copy in tcp header information
	memcpy(datagram_4 + sizeof(struct ip) , &tcphdr_4, sizeof(struct tcphdr));
	
	// sending tcp tail 2
	if(sendto(sockRaw, datagram_4, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0){
		perror("sendto failed");
		exit(1);
	}

	printf("Sent Sin Tail 2\n");
	close(sockRaw);

	

	printf("Standalone has completed\n");

	// free malloced data used for raw sock sending
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

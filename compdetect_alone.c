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
#include "cJSON.h"

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

instructions cJSON_make_struct( char * file, instructions settings){
	cJSON *json, *item, *object;
	json = cJSON_Parse(file);
	//add error catchers later
	//TODO MAKE item stuff go into settings
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip_address");
	//printf("getobejct got : %s\n", item->string);
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
	//printf("getobject got string %s, int value %d\n", item->string, item->valueint);
	if(item == NULL){
		printf("Missing source UDP prot in config file. Please include. Now Exiting \n");
		exit(0);
	}else{
		settings.sourceUDP_port=item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "destinationport_UDP");
	//printf("the %s is %d\n", item->string, item->valueint);
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
	//printf("the %s is %d\n", item->string, item->valueint);
	if(item == NULL){
		printf(" No regular TCP port, but can still continue.\n");
	}else{
		settings.port_TCP= item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "payload_sizeUDP");
	//printf("the %s is %d\n", item->string, item->valueint);
	if(item== NULL){
		settings.payload_size = 1000;
        }else{
		settings.payload_size= item->valueint;
	}



	item = cJSON_GetObjectItemCaseSensitive(json, "measure_time");
	//printf("the %s is %d\n", item->string, item->valueint);
	if(item== NULL){
		settings.measure_time= 15;
        }else{
		settings.measure_time= item->valueint;
	}


	item = cJSON_GetObjectItemCaseSensitive(json, "number_of_packets");
	//printf("the %s is %d\n", item->string, item->valueint);
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
	instructions config = read_file(argv[1]);

	char * serverip= config.server_ip;
	char * clientip= config.client_ip;
	int udp_source_port= config.sourceUDP_port;
	int udp_dest_port= config.destinationUDP_port;
	int tcp_sinHead= config.port_sinHead;
	int tcp_sinTail= config.port_sinTail;
	//TCP reg might not needed
	//int tcp_regPort= config.port_TCP;
	int payload= config.payload_size;
	int inter_measure_time= config.measure_time;
	int number_of_packets= config.num_of_paks;
	int timeToLive= config.timeTL;


	struct udpPacket{
		int length;
		char bytes[payload];
	};


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

}

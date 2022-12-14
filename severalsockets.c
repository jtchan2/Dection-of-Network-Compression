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

#define MAX_PAYLOAD_SIZE 2000
typedef struct
{
	char server_ip[100];
	char client_ip[100];
	int sourceUDP_port;
	int destinationUDP_port;
	int port_TCP;
	int payload_size;
	int measure_time;
	int num_of_paks;
}instructions;

//Parsing structure from Json

instructions cJSON_make_struct( char * file, instructions settings){
	cJSON *json, *item, *object;
	json = cJSON_Parse(file);
		
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip_address");
	
	if( item == NULL){
		printf("Missing server Ip address, please include in config.json\n");
		exit(1);
	}
	strcpy(settings.server_ip, item->valuestring);

	item =cJSON_GetObjectItemCaseSensitive(json, "client_ip_address");
	if(item == NULL){
		printf("Missing CLient Ip address, please include in config.json\n");
		exit(1);
	}
	strcpy(settings.client_ip, item->valuestring);

	item = cJSON_GetObjectItemCaseSensitive(json, "sourceport_UDP");

	if(item == NULL){
		printf("Missing UDP source port info in config.json, please include\n");
		exit(1);
	}
	settings.sourceUDP_port=item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "destinationport_UDP");
	
	if( item == NULL){
		printf("Missing UDP destination port please include in config.json\n");
		exit(1);
	}
	settings.destinationUDP_port=item->valueint;
	
	item = cJSON_GetObjectItemCaseSensitive(json, "port_TCP");
	
	if( item == NULL){
		printf("Missing TCP port in config.json, please include\n");
		exit(1);
	}
	settings.port_TCP= item->valueint;
	
	item = cJSON_GetObjectItemCaseSensitive(json, "payload_sizeUDP");
	
	if(item == NULL){
		settings.payload_size = 1000;
	}else{
		settings.payload_size= item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "measure_time");
	
	if(item == NULL){
		settings.measure_time = 15;
	}else{
		settings.measure_time= item->valueint;
	}

	item = cJSON_GetObjectItemCaseSensitive(json, "number_of_packets");
	
	if(item == NULL){
		settings.num_of_paks=6000;
	}else{
		settings.num_of_paks= item->valueint;
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
	printf("Getting Config information");
	instructions config= read_file(argv[1]);
	
	printf("Start Pre-probing TCP phase\n");

	int preprobe_socket;
	int num_of_packets=config.num_of_paks; // number of packets to send
	int size_payload=config.payload_size; // size of packet payloads
	int pause=config.measure_time; // used for making packet sending to have a break

	//Correct packet struct used for UDP packet sending
	struct pak{
		char byte_0_id; //lower order byte id
		char byte_1_id; //higher order byte id
		char data_payload[MAX_PAYLOAD_SIZE];
	};
	
	char buffer[3000];
	char msg[256];

	//created preprobe socket
	if( (preprobe_socket = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create Pre-probe Socket");
		exit(1);
	}
	//set variables to be used for socket creation
	int port; // port to be used for socket sending
	char *ip = config.server_ip; //server ip address
	char *clientip= config.client_ip; // client ip address
	struct sockaddr_in serveraddr;
	port = config.port_TCP;

	memset(&serveraddr, 0, sizeof(serveraddr));
	//Set ip address for Pre probe TCP 
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr= inet_addr(ip);

	//Connecting to server 
	int status = connect(preprobe_socket, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if(status <0){
		perror("Unable to connect to server");
		exit(1);
	}
	
	//Sending config information to the server from client config file
	sprintf(msg, "%d",config.destinationUDP_port);
	send(preprobe_socket, (char *) msg, sizeof(msg), 0);
	sprintf(msg, "%d", config.port_TCP);
	send(preprobe_socket, (char *) msg, sizeof(msg), 0);
	sprintf(msg, "%d", config.payload_size);
	send(preprobe_socket, (char *) msg, sizeof(msg), 0);
	sprintf(msg, "%d", config.num_of_paks);
	send(preprobe_socket, (char *)msg, sizeof(msg),0);
	sprintf(msg, "%d", config.measure_time);
	send(preprobe_socket, (char *)msg, sizeof(msg),0);

	close(preprobe_socket);
	printf("Sent 'config file'\n");

	printf("starting UDP probing Phase\n");

	//Start of UDP Phase
	int sockUDP;
	// change port for UDP sending
	port = config.destinationUDP_port;
	serveraddr.sin_port= htons(port);

	//created UDP socket
	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create Probing UDP socket");
		exit(1);
	}

	//Sett bindings for client udp  and setting memory
	struct sockaddr_in server_address, client_address;
	
	memset(&server_address, 0, sizeof(server_address));
	memset(&client_address, 0, sizeof(client_address));
	//set up ipaddress for server socket
	server_address.sin_family= AF_INET;
	server_address.sin_port = htons(port);
	server_address.sin_addr.s_addr = inet_addr(ip);

	port = config.sourceUDP_port;

	//set up ipaddress  for UDP sending for client socket
	client_address.sin_family= AF_INET;
	client_address.sin_port = htons(port);
	client_address.sin_addr.s_addr = inet_addr(clientip);

	int frag = IP_PMTUDISC_DO;
	setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &frag, sizeof(frag));
	//binds ip to socket
	if(bind(sockUDP, (struct sockaddr *) &client_address, sizeof(client_address))<0){
		perror("Unable to Bind UDP socket");
		exit(1);
	}
	//-------------------------------------------------------------

	sleep(5); //sleep used to make sure server and client are "sync"
		  //correctly for packet sendign and receiving
	printf("Now Sending Low entropy data packets\n");

	//creation of low packet data
	struct pak *low= (struct pak *)malloc(sizeof( struct pak));
	memset(&low->data_payload, 0, MAX_PAYLOAD_SIZE); // set mem of low packet to 0
	
	//sending low packet data wanted nubmer of times
	for( unsigned short int i=0; i<num_of_packets; i++){
		low->byte_0_id= (uint8_t)(i & 0xff); //setting lower order byte id
                low->byte_1_id= (uint8_t)(i >> 8); // setting higher order byte id
                //copy memory of low packet struct pointer to a string buffer
		memcpy(buffer, (char *) low, sizeof( struct pak));
		
		//send string buffer but only size of given paylaod +2 for account for id
		sendto(sockUDP,buffer, (size_payload+2), MSG_CONFIRM, (const struct sockaddr*) &server_address, sizeof(server_address));
		usleep(100);
	}
	printf("low packets sent\n");

	printf("Pausing to split UDP low packet data to send high entropy 'data'\n");
	sleep(pause); // sleeping code for given intermediate measure time by config file
	printf("Now Sending high entropy data\n");

	// Creating high entropy packet pointer
	struct pak * high= (struct pak*) malloc(sizeof(struct pak));


	//Opens up /dev/urandom file called rng and copies data into rngRandomdata to be used for high entropy packet sending
	char rngRandomData2[MAX_PAYLOAD_SIZE];
        unsigned int rngData2 = open("rng", O_RDONLY);
        read(rngData2,rngRandomData2, size_payload);
        close(rngData2);
	//copy memory of high entropy packet into high entropy packet pointer's payload
	memcpy(&high->data_payload, &rngRandomData2, MAX_PAYLOAD_SIZE);

	//creating High entropy data
	for(unsigned short int i=0; i<num_of_packets; i++){
		high->byte_0_id= (uint8_t)(i & 0xff); //writes lower byte id
                high->byte_1_id= (uint8_t)(i >> 8); // writes higher order byte id
		// copy packet pointer of high entropy data into a string buffer
		memcpy(buffer, (char *) high, sizeof(struct pak));
		//send buffer but only the size of given payload +2 for account for pack id
		sendto(sockUDP, buffer, (size_payload+2), MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
		usleep(100); //sleep to slow down sending to server
	}
	printf("Sent 'high entropy data'\n");
	printf("Ending Probing UDP phase\n");
	
	//freeing packets
	//free(low_entropy);
	free(low);
	free(high);

	close(sockUDP);
	
	printf("starting post probe TCP\n");

	//creating TCP post probe socket
	int postprobe_socket;

	//set port to postTCp port
	port = config.port_TCP;
	serveraddr.sin_port= htons(port);
	//create socket
	if( (postprobe_socket = socket (AF_INET, SOCK_STREAM, 0))<0){
		perror("COULD NOT CREATE POST PROBE PHASE SOCKET TCP");
		exit(1);
	}

	//setting client socket to connect to
	int PostprobeServer_sock;
	if( connect(postprobe_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("COULD NOT CONNECT POST PROBE TCP SOCKET");
		exit(1);
	}

	
	char timed[256];
	int n;
	//receiving comp dect message from server
	printf("Receiving Compression Result from Server\n");
	if( (n=recv(postprobe_socket,&timed, sizeof(timed), 0)) <0){
		perror("unable to Recieve message from Post Phase TCP");
		exit(1);
	}
	timed[n]='\0';
	//printing out compression results from server
	printf("Result : %s\n", timed);

	printf("ENDING TCP POST PROBE CONNECTION\n");
	close(postprobe_socket);
	close(PostprobeServer_sock);
		
	return 0;
}

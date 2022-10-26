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
	//add error catchers later
	//TODO MAKE item stuff go into settings	
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip_address");
	//printf("getobejct got : %s\n", item->string);
	strcpy(settings.server_ip, item->valuestring);


	item = cJSON_GetObjectItemCaseSensitive(json, "sourceport_UDP");
	//printf("getobject got string %s, int value %d\n", item->string, item->valueint);
	settings.sourceUDP_port=item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "destinationport_UDP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.destinationUDP_port=item->valueint;
	
	item = cJSON_GetObjectItemCaseSensitive(json, "port_TCP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.port_TCP= item->valueint;
	
	item = cJSON_GetObjectItemCaseSensitive(json, "payload_sizeUDP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.payload_size= item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "measure_time");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.measure_time= item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "number_of_packets");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.num_of_paks= item->valueint;

	item= cJSON_GetObjectItemCaseSensitive(json, "ttl");
	if(item == NULL){
		printf("COuld not find item\n");
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
	/*
	printf("%s\n",config.server_ip);
	printf("%d\n",config.sourceUDP_port);
	printf("%d\n",config.destinationUDP_port);
	printf("%d\n",config.port_TCP);
	printf("%d\n",config.payload_size);
	printf("%d\n",config.measure_time);
	printf("%d\n", config.num_of_paks);
	*/
	printf("Start Pre-probing TCP phase\n");
	int preprobe_socket;
	int num_of_packets=6000;
	int size_payload=1000;
	int pause=15;


	struct packet{
		int length;
		char bytes[size_payload];
	};
	char msg[256] = "config file";

	if( (preprobe_socket = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create Pre-probe Socket");
		exit(EXIT_FAILURE);
	}
	int port = 8765;
	char * ip= "192.168.86.248";
	struct sockaddr_in serveraddr;
	port = 8080;

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr= inet_addr(ip);

	int status = connect(preprobe_socket, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if(status <0){
		perror("Unable to connect to server");
		exit(EXIT_FAILURE);
	}
	
	send(preprobe_socket, (char *) msg, sizeof(msg), 0);

	close(preprobe_socket);
	printf("Sent 'config file'\n");

	printf("starting UDP probing Phase\n");

	//Start of UDP Phase
	int sockUDP;
	port = 8765;
	serveraddr.sin_port= htons(port);

	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create Probing UDP socket");
		exit(EXIT_FAILURE);
	}

	//attempting to chagne binding port of client
	struct sockaddr_in server_address, client_address;
	
	memset(&server_address, 0, sizeof(server_address));
	memset(&client_address, 0, sizeof(client_address));
	server_address.sin_family= AF_INET;
	server_address.sin_port = htons(port);
	server_address.sin_addr.s_addr = inet_addr(ip);

	client_address.sin_family= AF_INET;
	client_address.sin_port = htons(9876);
	client_address.sin_addr.s_addr = inet_addr("192.168.86.249");

	if(bind(sockUDP, (struct sockaddr *) &client_address, sizeof(client_address))<0){
		perror("Unable to Bind UDP socket");
		exit(EXIT_FAILURE);
	}

	//TODO Create actual packts to be sent not a message

	struct packet *low_entropy = (struct packet *) malloc (num_of_packets * sizeof(struct packet));

	struct packet *high_entropy = (struct packet *)malloc (num_of_packets * sizeof(struct packet));

	unsigned short id=0;;
	for(int i=0; i<num_of_packets; i++){
		low_entropy[i].length= size_payload;
		for( int j=0; j< (size_payload -2); j++){
			low_entropy[i].bytes[j]=0;
		}

		//id = i;
		char packid[2];
		packid[0]=id%256;
		packid[1]=id/256;
		id++;
		//sprintf(packid, "%d", id);

		char * payload = (char *) malloc(strlen(low_entropy[i].bytes)+ strlen(packid)+1);

		strcpy(payload, packid);
		
		strcat(payload, low_entropy[i].bytes);
		strcpy(low_entropy[i].bytes, payload);
		//strcpy(low_entropy[i].bytes, conversion);
	}


	//high entropy packet making
	//
	unsigned char rngRandomData[size_payload];

	unsigned int rngData = open("rng", O_RDONLY);
	read(rngData,rngRandomData, size_payload);
	close(rngData);
	
	for(int i=0; i<num_of_packets; i++){
                high_entropy[i].length= size_payload;
                for( int j=0; j< (size_payload -2); j++){
                        high_entropy[i].bytes[j]=rngRandomData[j];
                }

                //id = i;
                char packid[2];
		packid[0]=id%256;
		packid[1]=id/256;
		id++;
                //sprintf(packid, "%d", id);

                char * payload = (char *) malloc(strlen(high_entropy[i].bytes)+ strlen(packid)+1);

                strcpy(payload, packid);

                strcat(payload, high_entropy[i].bytes);
                strcpy(high_entropy[i].bytes, payload);
                //strcpy(high_entropy[i].bytes, conversion);
        }


	char * packet= "Packet";

	for( int i=0; i<num_of_packets; i++){
		//change MSG_CONFIRM to 0 maybe
		sendto(sockUDP, low_entropy[i].bytes, sizeof(low_entropy[i].bytes), MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
	}
	printf("packet sent\n");

	printf("Pausing to split UDP low to high entropy 'data'\n");
	sleep(pause);
	printf("Now Sending high entropy data\n");

	for(int i=0; i<num_of_packets; i++){
		//change MSG_CONFIRM to 0 maybe
		sendto(sockUDP, high_entropy[i].bytes, sizeof(high_entropy[i].bytes), MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
	}
	printf("Sent 'high entropy data'\n");
	printf("Ending Probing UDP phase\n");
	//close(sockUDP);
	shutdown(sockUDP, 1);
	
	printf("starting post probe TCP\n");

	int postprobe_socket;

	port = 8080;
	serveraddr.sin_port= htons(port);
	if( (postprobe_socket = socket (AF_INET, SOCK_STREAM, 0))<0){
		perror("COULD NOT CREATE POST PROBE PHASE SOCKET TCP");
		exit(EXIT_FAILURE);
	}

	sleep(5);

	/*
	int yes =1;
	setsockopt(postprobe_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	*/
	int PostprobeServer_sock;
	if( connect(postprobe_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("COUKD NOT CONNECT POST PROBE TCP SOCKET");
		exit(EXIT_FAILURE);
	}

	//int PostprobeServer_sock;
	char timed[256];
	int n;
	if( (n=recv(postprobe_socket,&timed, sizeof(timed), 0)) <0){
		perror("unable to Recieve message from Post Phase TCP");
		exit(EXIT_FAILURE);
	}
	timed[n]='\0';
	printf("Time : %s\n", timed);

	printf("ENDING TCP POST PROBE CONNECTION\n");
	close(postprobe_socket);
	close(PostprobeServer_sock);
		
	return 0;
}

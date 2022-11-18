#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include "cJSON.h"

typedef struct{
	char server_ip[100];
	int port_TCP;
}instructions;

instructions cJSON_make_struct(char* file, instructions settings){
	cJSON *json, *item;
	json = cJSON_Parse(file);
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip");
	strcpy(settings.server_ip, item->valuestring);
	item = cJSON_GetObjectItemCaseSensitive(json, "port_TCP");
	settings.port_TCP= item->valueint;

	cJSON_Delete(json);

	return settings;
}

size_t get_file_size(const char *filepath){
	if(filepath== NULL){
		printf("Incorrect file path");
		return 0;
	}

	struct stat filestat;
	memset(&filestat, 0, sizeof(struct stat));

	//gets information
	if(stat(filepath, &filestat)==0){
		return filestat.st_size;
	}else{
		return 0;
	}
}

instructions read_file (char *filename){
	FILE *fp;
	instructions config;
	size_t size = get_file_size(filename);
	if(size == 0){
		printf("failed to get file path size\n");
	}
	char * bufr = malloc (size +1);
	if(bufr == NULL){
		printf ("Malloc fialed\n");
	}

	memset(bufr, 0, size+1);
	fp= fopen(filename, "rb");

	fread(bufr, 1, size, fp);

	fclose(fp);
	config = cJSON_make_struct(bufr, config);
	free(bufr);
	
	printf("finished reading and parsing config file\n");
	return config;
}

void cleanExit(){
exit(0);
}
int main (int argc, char *argv[]){
	
	// pre config file recieving from Server
	printf("Getting config file Information\n");
	instructions config= read_file(argv[1]);
	
	
	int preprobe_socket;
	int frag = IP_PMTUDISC_DO;
	
	printf("Starting Pre Probing TCP phase\n");
	
	if( (preprobe_socket= socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create pre probing Socket");
		exit(1);
	}
	int port;
	char * ip= config.server_ip;
	struct sockaddr_in serveraddr;

	port = config.port_TCP;
	memset(&serveraddr, 0, sizeof(serveraddr));	
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port= htons(port);
	serveraddr.sin_addr.s_addr= inet_addr(ip);

	setsockopt(preprobe_socket, SOL_SOCKET, SO_REUSEADDR, &frag, sizeof(frag));
	if( bind(preprobe_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("Unable to bind pre probing socket");
		exit(1);
	}

	listen(preprobe_socket, 5);

	int ppclient_socket;
	struct sockaddr_storage client_addr;
	socklen_t addr_size;
	addr_size = sizeof(client_addr);

	if( (ppclient_socket = accept(preprobe_socket, (struct sockaddr*) &client_addr, &addr_size)) <0){
		perror("Unable to accept Pre probing SOcket");
		exit(1);
	}
	char destination_UDP[256];
	char port_TCP[256];
	char paySize [256];
	char numOfPaks [256];
	int n;

	if( (n = recv (ppclient_socket, destination_UDP, sizeof(destination_UDP), 0))<0){
		perror("Unable to recieve message from Pre Probe socket");
		exit(1);
	}

	// Setting of variables after reading/ receiving information from client
	destination_UDP[n]='\0';
	n=recv(ppclient_socket, port_TCP, sizeof(port_TCP), 0);
	port_TCP[n]='\0';
	n=recv(ppclient_socket, paySize, sizeof(paySize), 0);
	paySize[n]='\0';
	n=recv(ppclient_socket, numOfPaks, sizeof(numOfPaks), 0);
	numOfPaks[n]='\0';

	
	port = atoi(destination_UDP);
	int size_payload = atoi(paySize);
	char bytes[size_payload];
	int num_of_packets= atoi(numOfPaks);

	printf("Ending Pre Probing TCP phase\n");
	close(ppclient_socket);
	close(preprobe_socket);


	printf("Starting Probing UDP phase\n");


	// socket to be used for UDp packet sending
	int sockUDP;
	struct sockaddr_in serveraddrUDP, clientaddrUDP;
	
	memset(&serveraddrUDP, 0, sizeof(serveraddrUDP));
	memset(&clientaddrUDP, 0, sizeof(clientaddrUDP));
	
	serveraddrUDP.sin_family = AF_INET;
	serveraddrUDP.sin_port= htons(port);
	serveraddrUDP.sin_addr.s_addr=inet_addr(ip);


	if( (sockUDP= socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("Unable to create UDP socket");
		exit(1);
	}

	

	setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &frag, sizeof(frag));
	
	printf("created UDP socket\n");
	if ( bind(sockUDP, (const struct sockaddr *) &serveraddrUDP, sizeof(serveraddrUDP))< 0){
		perror("Not able to bind UDP socket");
		exit(1);
	}
	printf("Binded Socket\n");

	printf("Now Receiving Low Entropy packets\n");


	// create Post TCP here
	int post_sock;
	port= atoi(port_TCP);
	if( (post_sock = socket (AF_INET, SOCK_STREAM, 0))<0){
                perror("Unable to connect Post Probing TCP socket");
                exit(1);
        }


        setsockopt(post_sock, SOL_SOCKET, SO_REUSEADDR, &frag, sizeof(frag));

        if( bind(post_sock, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
                perror("Unable to Bind Post probing TCP");
                exit(1);
        }
	int checkycheck;
        if((checkycheck=listen(post_sock, 5))<0){
                perror("Not able to listen for Post Probing Phase TCP");
                exit(1);
        }

	


// tcp created here 

	clock_t timer;
	
	int len= sizeof(clientaddrUDP);
	timer = clock();
	for(int i=0; i<num_of_packets; i++){

		n = recvfrom(sockUDP, bytes, sizeof(bytes), MSG_WAITALL, (struct sockaddr *) &clientaddrUDP,&len);
		
		
	}
	timer = clock()-timer;
	double time_taken = ((double)timer)/CLOCKS_PER_SEC;
	
	printf("recieved Low Entropy packets\n");
	printf("\n");
	printf("Recieving 'high entropy data/packets' after a short break\n");
	printf("\n");

	printf("Now Recieve high entropy data packets'\n");
	clock_t timer2;
	timer2=clock();
	for(int i=0; i<num_of_packets; i++){
		n = recvfrom(sockUDP, bytes, sizeof(bytes), MSG_WAITALL, (struct sockaddr *) & clientaddrUDP, &len);
		
	}
	
	timer2= clock()-timer2;
	double time_taken2= ((double)timer2)/CLOCKS_PER_SEC;
	
	printf("recieved High entropy packts\n");

	printf("Probing UDP phase ending\n");
	close(sockUDP);
	
	//Does math of finding time difference in seconds then converts to MS
	double time_overall = (time_taken2 - time_taken)*((double)1000);
	char  *mille;
	if(time_overall >((double)100)){
		mille="Compression Detected!";
	}else{
		mille="No compression was Detected";
	}
	
	printf("Is There Compressions? : %s \n", mille);
	

	printf("Starting Post probing phase TCP\n");

	
	//TCP post now accepting any incoming TCP connections
	int client_sockPost;
	
		
	if((client_sockPost= accept(post_sock, (struct sockaddr*) &client_addr, &addr_size))<0){
		perror("Not able to Accept for Post Probing pahse TCP");
		exit(1);
	}
	
	
	int bytez;
	bytez =send(client_sockPost, (char *)mille, strlen(mille), 0);
	if(bytez<1){
		printf("Nothing was sent\n");

	}
	printf("Sent Client time results\n");
	printf("ending post probing phase\n");
	close(post_sock);
	close(client_sockPost);
	
	return 0;
}		

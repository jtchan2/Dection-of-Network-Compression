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
	int port_TCP;
}instructions;

instructions cJSON_make_struct(char* file, instructions settings){
	cJSON *json, *item;
	json = cJSON_Parse(file);
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
	//int size_payload=1000;
	//int num_of_packets=6000;
	//char bytes[size_payload];
	
	printf("Getting config file Information\n");
	instructions config= read_file(argv[1]);
	printf("%d\n", config.port_TCP);
	
	int preprobe_socket;
	int frag = IP_PMTUDISC_DO;
	printf("Starting Pre Probing TCP phase\n");
	if( (preprobe_socket= socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create pre probing Socket");
		exit(EXIT_FAILURE);
	}
	int port;
	char * ip= "192.168.86.248";
	struct sockaddr_in serveraddr;

	port = config.port_TCP;
	memset(&serveraddr, 0, sizeof(serveraddr));	
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port= htons(port);
	serveraddr.sin_addr.s_addr= inet_addr(ip);

	setsockopt(preprobe_socket, SOL_SOCKET, SO_REUSEADDR, &frag, sizeof(frag));
	if( bind(preprobe_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("Unable to bind pre probing socket");
		exit(EXIT_FAILURE);
	}

	listen(preprobe_socket, 5);

	int ppclient_socket;
	struct sockaddr_storage client_addr;
	socklen_t addr_size;
	addr_size = sizeof(client_addr);
	if( (ppclient_socket = accept(preprobe_socket, (struct sockaddr*) &client_addr, &addr_size)) <0){
		perror("Unable to accept Pre probing SOcket");
		exit(EXIT_FAILURE);
	}
	char destination_UDP[256];
	char port_TCP[256];
	char paySize [256];
	char numOfPaks [256];
	int n;

	if( (n = recv (ppclient_socket, destination_UDP, sizeof(destination_UDP), 0))<0){
		perror("Unable to recieve message from Pre Probe socket");
		exit(EXIT_FAILURE);
	}
	destination_UDP[n]='\0';
	n=recv(ppclient_socket, port_TCP, sizeof(port_TCP), 0);
	port_TCP[n]='\0';
	n=recv(ppclient_socket, paySize, sizeof(paySize), 0);
	paySize[n]='\0';
	n=recv(ppclient_socket, numOfPaks, sizeof(numOfPaks), 0);
	numOfPaks[n]='\0';

	/*	
	printf("CLient has sent : %s\n", destination_UDP);
	printf("%s\n", port_TCP);
	printf("%s\n", paySize);
	printf("%s\n", numOfPaks);
	*/
	port = atoi(destination_UDP);
	int size_payload = atoi(paySize);
	char bytes[size_payload];
	int num_of_packets= atoi(numOfPaks);

	printf("Ending Pre Probing TCP phase\n");
	close(ppclient_socket);
	close(preprobe_socket);


	printf("Starting Probing UDP phase\n");

	signal(SIGTERM, cleanExit);
	signal(SIGINT, cleanExit);

	// socket to be used for UDp packet sending
	int sockUDP;
	struct sockaddr_in serveraddrUDP, clientaddrUDP;
	
	memset(&serveraddrUDP, 0, sizeof(serveraddrUDP));
	memset(&clientaddrUDP, 0, sizeof(clientaddrUDP));
	port = 8765;
	serveraddrUDP.sin_family = AF_INET;
	serveraddrUDP.sin_port= htons(port);
	serveraddrUDP.sin_addr.s_addr=inet_addr(ip);


	if( (sockUDP= socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("Unable to create UDP socket");
		exit(EXIT_FAILURE);
	}

	

	setsockopt(sockUDP, IPPROTO_IP, IP_MTU_DISCOVER, &frag, sizeof(frag));
	
	printf("created UDP socket\n");
	if ( bind(sockUDP, (const struct sockaddr *) &serveraddrUDP, sizeof(serveraddrUDP))< 0){
		perror("Not able to bind UDP socket");
		exit(EXIT_FAILURE);
	}
	printf("Binded Socket\n");


	//trying to create TCP here
	int post_sock;
	port= atoi(port_TCP);
	if( (post_sock = socket (AF_INET, SOCK_STREAM, 0))<0){
                perror("Unable to connect Post Probing TCP socket");
                exit(EXIT_FAILURE);
        }


        setsockopt(post_sock, SOL_SOCKET, SO_REUSEADDR, &frag, sizeof(frag));

        if( bind(post_sock, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
                perror("Unable to Bind Post probing TCP");
                exit(EXIT_FAILURE);
        }
	int checkycheck;
        if((checkycheck=listen(post_sock, 5))<0){
                perror("Not able to listen for Post Probing Phase TCP");
                exit(EXIT_FAILURE);
        }

	/* trying to find out when a connection is queued
	int client_sockPost;
	if((client_sockPost= accept(post_sock, (struct sockaddr*) &client_addr, &addr_size))<0){
                perror("Not able to Accept for Post Probing pahse TCP");
                exit(EXIT_FAILURE);
        }
	*/


// tcp created here 

	clock_t timer;
	printf("Now Receiving\n");

	//bind client addrUDP to a different port= 9876
	int len= sizeof(clientaddrUDP);
	timer = clock();
	for(int i=0; i<num_of_packets; i++){
		n = recvfrom(sockUDP, bytes, sizeof(bytes), MSG_WAITALL, (struct sockaddr *) &clientaddrUDP,&len);
		/*
		if(n<0){
	                perror("Unable to recive packets UDP style");
        	        exit(EXIT_FAILURE);
	       	}
		if(n==0){
			perror("SOCKET CLOSED BOFRE ALL DATA SENT");
			exit(EXIT_FAILURE);
		}
		*/
	}
	timer = clock()-timer;
	double time_taken = ((double)timer)/CLOCKS_PER_SEC;
	/*
	gainer[n] = '\0';
	printf("Server Recieved : %s, time: %f\n", gainer, time_taken);
	*/
	printf("recieved packets\n");
	printf("Recieving 'high entropy data/packets' after a short break\n");
	//sleep(15);

	printf("Now Recieve 'high entropy dat packets'\n");
	clock_t timer2;
	timer2=clock();
	for(int i=0; i<num_of_packets; i++){
		n = recvfrom(sockUDP, bytes, sizeof(bytes), MSG_WAITALL, (struct sockaddr *) & clientaddrUDP, &len);
		/*
		if(n<0){
			perror(" Unable to recieve high entropy packets UDP style");
			exit(EXIT_FAILURE);
		}
		*/

	}
	
	timer2= clock()-timer2;
	double time_taken2= ((double)timer2)/CLOCKS_PER_SEC;
	/*
	gainer[n] = '\0';
	printf("Server Recieved High data : %s, time taken: %f\n", gainer,time_taken2);
	*/
	printf("recieved packts\n");

	printf("Probing UDP phase ending\n");
	close(sockUDP);
	//Does math of finding time difference in seconds then converts to MS
	double time_overall = (time_taken2 - time_taken)*((double)1000);
	char  *mille;
	if(time_overall >((double)100)){
		mille="Compression Detected!";
	}else{
		mille="No compression was Dected";
	}
	//sprintf(mille, "%f", time_overall);
	printf("Time difference is %s ms\n", mille);
	

	printf("Starting Post probing phase TCP\n");

	//TESTING MOVING TCP UP
	//int post_sock;

	//port=8080;
	//port= atoi(port_TPC);

	/*
	if( (post_sock = socket (AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to connect Post Probing TCP socket");
		exit(EXIT_FAILURE);
	}

	
        setsockopt(post_sock, SOL_SOCKET, SO_REUSEADDR, &frag, sizeof(frag));

	if( bind(post_sock, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("Unable to Bind Post probing TCP");
		exit(EXIT_FAILURE);
	}

	if(listen(post_sock, 5)<0){
		perror("Not able to listen for Post Probing Phase TCP");
		exit(EXIT_FAILURE);
	}
	*/
	//try to get notification when accept arrives
	//printf("%d\n", checkycheck);
	int client_sockPost;
	//may need to add new client_addr and addr_size
	//
	
	if((client_sockPost= accept(post_sock, (struct sockaddr*) &client_addr, &addr_size))<0){
		perror("Not able to Accept for Post Probing pahse TCP");
		exit(EXIT_FAILURE);
	}
	

	char * letter="Was this sent?";
	
	int bytez;
	bytez =send(client_sockPost, (char *)mille, strlen(mille), 0);
	if(bytez<1){
		printf("Nothing was sent\n");
		printf("size of Byte %d, size of letter %ld\n",bytez, strlen(letter));
	}
	printf("Sent Client time results\n");
	printf("ending post probing phase\n");
	close(post_sock);
	close(client_sockPost);
	
	return 0;
}	

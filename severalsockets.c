#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]){
	printf("Start Pre-probing TCP phase\n");
	int preprobe_socket;

	char msg[256] = "config file";

	if( (preprobe_socket = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create Pre-probe Socket");
		exit(EXIT_FAILURE);
	}
	int port = 8765;
	char * ip= "192.168.86.248";
	struct sockaddr_in preserveraddr;
	port = 8080;

	//memset(&serveraddr, 0, sizeof(serveraddr));
	preserveraddr.sin_family = AF_INET;
	preserveraddr.sin_port=htons(port);
	preserveraddr.sin_addr.s_addr= inet_addr(ip);

	int status = connect(preprobe_socket, (struct sockaddr*)&preserveraddr, sizeof(preserveraddr));
	if(status <0){
		perror("Unable to connect to server");
		exit(EXIT_FAILURE);
	}
	
	send(preprobe_socket, (char *) msg, sizeof(msg), 0);

	close(preprobe_socket);
	printf("Sent 'config file'\n");

	printf("starting UDP probing Phase\n");

	int sockUDP;
	port = 8765;
	

	struct sockaddr_in serveraddrUDP, clientaddrUDP;

	serveraddrUDP.sin_family = AF_INET;
	serveraddrUDP.sin_addr.s_addr = inet_addr(ip);
	serveraddrUDP.sin_port= htons(port);

	port = 9876;

	clientaddrUDP.sin_family = AF_INET;
	clientaddrUDP.sin_addr.s_addr = inet_addr(ip);
	clientaddrUDP.sin_port = htons(port);

	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create Probing UDP socket");
		exit(EXIT_FAILURE);
	}

	//bind sockUDP to port 9876	
	
	if(bind(sockUDP, (struct sockaddr*)&clientaddrUDP, sizeof(clientaddrUDP))<0){
		perror("Could not bind UDP socket to port 9876");
		exit(EXIT_FAILURE);
	}

	char * packet= "Packet";

	for( int i=0; i<6000; i++){
		sendto(sockUDP, (const char *)packet, strlen(packet), MSG_CONFIRM, (const struct sockaddr *) &serveraddrUDP, sizeof(serveraddrUDP));
	}
	printf("packet sent\n");

	printf("Pausing to split UDP low to high entropy 'data'\n");
	sleep(15);
	printf("Now Sending high entropy data\n");

	for(int i=0; i<6000; i++){
		sendto(sockUDP, (const char *) packet, strlen(packet), MSG_CONFIRM, (const struct sockaddr *) &serveraddrUDP, sizeof(serveraddrUDP));
	}
	printf("Sent 'high entropy data'\n");
	printf("Ending Probing UDP phase\n");
	//close(sockUDP);
	shutdown(sockUDP, 1);
	
	printf("starting post probe TCP\n");

	int postprobe_socket;

	port = 8080;
	struct sockaddr_in postserveraddr;
	postserveraddr.sin_family = AF_INET;
	postserveraddr.sin_addr.s_addr=inet_addr(ip);
	postserveraddr.sin_port= htons(port);
	if( (postprobe_socket = socket (AF_INET, SOCK_STREAM, 0))<0){
		perror("COULD NOT CREATE POST PROBE PHASE SOCKET TCP");
		exit(EXIT_FAILURE);
	}

	sleep(10);

	/*
	int yes =1;
	setsockopt(postprobe_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	*/
	int PostprobeServer_sock;
	if( connect(postprobe_socket, (struct sockaddr*) &postserveraddr, sizeof(postserveraddr))<0){
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

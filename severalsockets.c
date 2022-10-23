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

	int sockUDP;
	port = 8765;
	serveraddr.sin_port= htons(port);

	if( (sockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("Unable to create Probing UDP socket");
		exit(EXIT_FAILURE);
	}

	//attempting to chagne binding port of client
	struct sockaddr_in server_address, client_address;
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

	//bind sockUDP to port 9876	

	char * packet= "Packet";

	for( int i=0; i<6000; i++){
		sendto(sockUDP, (const char *)packet, strlen(packet), MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
	}
	printf("packet sent\n");

	printf("Pausing to split UDP low to high entropy 'data'\n");
	sleep(15);
	printf("Now Sending high entropy data\n");

	for(int i=0; i<6000; i++){
		sendto(sockUDP, (const char *) packet, strlen(packet), MSG_CONFIRM, (const struct sockaddr *) &server_address, sizeof(server_address));
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

	sleep(10);

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

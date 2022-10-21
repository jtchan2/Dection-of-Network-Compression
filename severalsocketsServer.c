#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

int main (int argc, char *argv[]){
	int preprobe_socket;

	if( (preprobe_socket= socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create pre probing Socket");
		exit(EXIT_FAILURE);
	}
	int port = 8765;
	char * ip= "192.168.86.248";
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port= htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ip);

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
	char msg[256];
	int n;

	if( (n = recv (ppclient_socket, msg, sizeof(msg), 0))<0){
		perror("Unable to recieve message from Pre Probe socket");
		exit(EXIT_FAILURE);
	}
	msg[n]='\0';
	printf("CLient has sent : %s\n", msg);

	close(ppclient_socket);
	close(preprobe_socket);

	return 0;


}

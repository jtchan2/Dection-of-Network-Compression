#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#define MAXLINE 1024

int main (int argc, char * argv[]){

	int sock_UDP,sock_Pre, sock_Post,port;
	char *ip;
	char buffer[MAXLINE];
	struct sockaddr_in serveraddr;
	int len, bytes_sent;
	char* msg= "Here is Config File";

	if( (sock_Pre = socket(AF_INET, SOCK_STREAM, 0))<0){
                perror("Failed to Create Pre Probing Socket");
                exit(EXIT_FAILURE);
        }

	ip="192.168.86.248";
	port= 8765;
	memset( &serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ip);

	

	if(connect(sock_Pre, (struct sockaddr*)&serveraddr, sizeof(serveraddr))<0){
		perror("Failed to connect Pre Probing Socket");
		exit(EXIT_FAILURE);
	}
	len = strlen(msg);
	bytes_sent = send(sock_Pre, (char *)msg, len, 0);
	if (bytes_sent<0){
		printf("Nothing was sent\n");
	}
	printf("Sent config File to server\n");
	close(sock_Pre);

}

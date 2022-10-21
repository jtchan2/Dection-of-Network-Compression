#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>

int main( int argc, char *argv[]){
	//some variables such as packets, ip and port will be later changed to config stuff
	int sock_UDP, client_sock, packets, port;
	char *ip;
	char *info;
	struct sockaddr_in serveraddr, clientaddr;
	clock_t timer;
	if( (sock_UDP = socket(AF_INET, SOCK_DGRAM, 0))< 0) {
		perror("Could not Create socket");
		exit(EXIT_FAILURE);
	}
	ip= "192.168.86.248";
	port= 8080;
	packets=6000;
	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(ip);
	serveraddr.sin_port= htons(port);

	if( bind (sock_UDP,(const struct sockaddr *)&serveraddr, sizeof(serveraddr)) <0){
		perror("Not able to bind socket");
		exit(EXIT_FAILURE);
	}

	int len, n;
	len= sizeof(clientaddr);
	for(int i=0; i<packets; i++){
		n = recvfrom(sock_UDP, ( char *)info, sizeof(info), MSG_WAITALL, (struct sockaddr*)&clientaddr, &len);
	}

	close(sock_UDP);
	return 0;

}

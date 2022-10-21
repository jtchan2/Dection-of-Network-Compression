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
	int sock_UDP, sockfd,client_sock, packets, port, sockList1, sockList2;
	char *ip;
	char *info;
	struct sockaddr_in serveraddr, clientaddr;
	struct sockaddr_storage client_addr;
	socklen_t addr_size;
	char buffer[1042];
	clock_t timer;
	

	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) <0){
		perror("socket Creation failed");
		exit(EXIT_FAILURE);
	}
	
	/* UDP SOCKET
	if( (sock_UDP = socket(AF_INET, SOCK_DGRAM, 0))< 0) {
		perror("Could not Create socket");
		exit(EXIT_FAILURE);
	}
	*/
	ip= "192.168.86.248";
	port= 8765;
	packets=6000;
	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(ip);
	serveraddr.sin_port= htons(port);

	if(bind(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr))<0){
		perror("Not able to bind Pre Probing TCP Socket");
		exit(EXIT_FAILURE);
	}

	if(listen(sockfd, 2)<0){
		perror("Not able to Listen");
		exit(EXIT_FAILURE);
	}
	addr_size=sizeof(client_addr);
	if(sockList1= accept(sockfd, (struct sockaddr*)&client_addr, &addr_size)<0){
		perror("Not able to Accept Pre Probe Sock Listner");
		exit(EXIT_FAILURE);
	}

	int n;
	//error with recieving packet
	n = recv(sockList1, buffer, sizeof(buffer),0);
	if(n<0){
		perror("Not ABle to Recieve config from Pre Probing Phase");
		exit(EXIT_FAILURE);
	}
	buffer[n]='\0';
	printf("MEssage from Client: %s\n", buffer);

	close(sockList1);
	close(sockfd);

	/*
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
	*/
	return 0;

}

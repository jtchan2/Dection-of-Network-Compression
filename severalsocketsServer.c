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

int main (int argc, char *argv[]){
	int preprobe_socket;

	printf("Starting Pre Probing TCP phase\n");
	if( (preprobe_socket= socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to create pre probing Socket");
		exit(EXIT_FAILURE);
	}
	int port = 8765;
	char * ip= "192.168.86.248";
	struct sockaddr_in serveraddr;

	port = 8080;
	memset(&serveraddr, 0, sizeof(serveraddr));	
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
	printf("Ending Pre Probing TCP phase\n");
	close(ppclient_socket);
	close(preprobe_socket);

	printf("Starting Probing UDP phase\n");

	// socket to be used for UDp packet sending
	int sockUDP;
	struct sockaddr_in clientaddrUDP;
	port = 8765;

	serveraddr.sin_port= htons(port);
	if( (sockUDP= socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("Unable to create UDP socket");
		exit(EXIT_FAILURE);
	}
	printf("created UDP socket\n");
	if ( bind(sockUDP, (const struct sockaddr *) &serveraddr, sizeof(serveraddr))< 0){
		perror("Not able to bind UDP socket");
		exit(EXIT_FAILURE);
	}
	printf("Binded Socket\n");

	clock_t timer;
	char gainer[256];

	//bind client addrUDP to a different port= 9876
	int len= sizeof(clientaddrUDP);
	timer = clock();
	for(int i=0; i<6000; i++){
		n = recvfrom(sockUDP, (char *) gainer, 256, MSG_WAITALL, (struct sockaddr *) &clientaddrUDP,&len);
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
	for(int i=0; i<6000; i++){
		n = recvfrom(sockUDP, (char *) gainer, 256, MSG_WAITALL, (struct sockaddr *) & clientaddrUDP, &len);
		/*
		if(n<0){
			perror(" Unable to recieve high entropy packets UDP style");
			exit(EXIT_FAILURE);
		}
		*/
	}
	
	timer2= clock()-timer;
	double time_taken2= ((double)timer)/CLOCKS_PER_SEC;
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

	int post_sock;

	port=8080;
	struct sockaddr_in postserveraddr;
	postserveraddr.sin_family= AF_INET;
	postserveraddr.sin_port= htons(port);
	postserveraddr.sin_addr.s_addr= inet_addr(ip);


	if( (post_sock = socket (AF_INET, SOCK_STREAM, 0))<0){
		perror("Unable to connect Post Probing TCP socket");
		exit(EXIT_FAILURE);
	}

	int yes =1;
        setsockopt(post_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	if( bind(post_sock, (struct sockaddr*) &postserveraddr, sizeof(postserveraddr))<0){
		perror("Unable to Bind Post probing TCP");
		exit(EXIT_FAILURE);
	}

	if(listen(post_sock, 5)<0){
		perror("Not able to listen for Post Probing Phase TCP");
		exit(EXIT_FAILURE);
	}

	int client_sockPost;
	//may need to add new client_addr and addr_size
	if((client_sockPost= accept(post_sock, (struct sockaddr*) &client_addr, &addr_size))<0){
		perror("Not able to Accept for Post Probing pahse TCP");
		exit(EXIT_FAILURE);
	}

	char * letter="Was this sent?";
	
	int bytes;
	bytes =send(client_sockPost, (char *)mille, strlen(mille), 0);
	if(bytes<1){
		printf("Nothing was sent\n");
		printf("size of Byte %d, size of letter %ld\n",bytes, strlen(letter));
	}
	printf("Sent Client time results\n");
	printf("ending post probing phase\n");
	close(post_sock);
	close(client_sockPost);
	//hello
	
	return 0;


}

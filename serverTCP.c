#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8765
#define MAXLINE 1024
#define BACKLOG 10

int main (int argc, char *argv[]){
	int sockfd, new_fd;
	struct sockaddr_in serveraddr, clientaddr;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	char buffer[MAXLINE];

	if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) <0){
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));

	serveraddr.sin_family= AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr("192.168.86.248");
	serveraddr.sin_port = htons(PORT);

	if( bind(sockfd, ( struct sockaddr*)&serveraddr, sizeof(serveraddr))<0){
		perror("not able to bind socket");
		exit(EXIT_FAILURE);
	}

	/*In case bind fails stating 'Address already in use' Do this:
	 * int yes =1;
	 * if( setsockopt(listener, SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) ==-1){
	 *perror("setsockopt");
	 exit(1);
	 * }
	 */

	listen(sockfd, BACKLOG);

	addr_size= sizeof(their_addr);
	new_fd= accept(sockfd, ( struct sockaddr*)&their_addr, &addr_size);
	if(new_fd < 0){
		printf("Error  accepting client");
		return -1;
	}
	int n;
	if((n= recv( new_fd, buffer, sizeof(buffer), 0)) <0){
		printf("can not receive message\n");
		return -1;
	}
	buffer[n]='\0';
	printf("Message from Client: %s\n", buffer);
	
	close(new_fd);
	close(sockfd);
	return 0;
}

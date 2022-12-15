CONTENTS OF THIS FILE
------------------------
*Group members
*Requirements
*Instructions
*Incomplete Features
*Design explanation
*Code Issues
-------------------

Group Members
---------------
Aaron Brion
Justin Chan 20542444


*Requirements
---------------
The require files needed to run client-server would be:
severalsockets.c [client code]
severalSocketsServer.c [server code]
config.json
configserve.json


Files need for standalone program:
compdetect_alone.c [standalone code]
config.json

Need to have cJSON.c and cJSON.h in file directory where ever running code
as they are the items used to parse and read config files.

If you have a need to provide own config files for programs make sure to follow specific json structure
for both configs ex:
for client config.json structure:
{
	"server_ip_address":"Serve Ip address",
	"client_ip_address":"Client ip adress",
	"sourceport_UDP": 9876,
	"destinationport_UDP":8765,
	"TCP_Head_Syn": 8000,
	"TCP_Tail_Syn": 8001,
	"port_TCP":8080,
	"payload_sizeUDP":1000,
	"measure_time":15,
	"number_of_packets":6000,
	"ttl": 200
}

For making or using own configserve json do structure:
{
	"server_ip":"192.168.86.248",
	"port_TCP":8080
}

NOTE: TAKE ALL FILES FROM GIVEN ZIP, can exclude pcap files AND PUT INTO DIRECTORY YOU WANT TO
RUN CODE BEFORE COMPILING AND RUNNING CODE

Instructions
----------------

First to compile code for client-server program do:
1. To compile server do : gcc cJSON.c severalsocketsServer.c -o severalsocketsServer -lm
2. To Compile CLient do: gcc cJSON.c severalsockets -o severalsockets -lm

To compile code for standalone do :
4.  to compile standalone do : gcc cJSON.c compdetect_alone.c -o compdetect_alone -lm

To run client server program do:
First run: ./severalsocketsServer configserve.json 
in server vm or machine
Then do: ./severalsockets config.json 
in client vm or machine
NOTE: MAKE SURE TO RUN SERVER CODE FIRST BEFORE RUNNING CLIENT CODE


To run standalone code do:
sudo ./compdetect_alone config.json



Incomplete Features
--------------------
In my code the parts of the project I failed to implement is for the standalone.
Where I wasnt able to implement packet sniffing for receiving RST packets for standalone
feature. Additionally I wasnt able to implement the timer for the receiving of the RST packets
and printing out a result to the user



Design Explanation
------------------
For my packet creation, I decided to go with approach of using a struct called packet
where it would hold 3 memebrs: char byte 0 id, char byte 1 id, and char payload[MAX_PAYLOAD_SIZE].
the char bytes would represent the ids of the packets and payload would represent the paylaod of a packet.
To create packets of would memset low packet paylaod to 0, and in for loop for sending packet,
I would increment the id by bit shifting the value of i and setting it to ids of packet struct.
Then I would copy paylaod into a string buffer and sendto the buffer where the size of buffer would
be defined paylaod size + 2 to account for id. High entropy is very similar as instead it would copy
data from /dev/urandom file called rng and memcpy the data into the payload of the high entropy
packet payload then in for loop for sending would follow same process of low entropy sending.

Another code design I have chose is for the client-servder application, in the severalsocketsServe.c code, I have chosen to
create the TCP Post probe socket creation right after creating the UDP probing socket. I chosen to do this because 
I wanted to ensure that when the client has finished sending packets to the server, it wouldn't connect or a un opened
socket of receive a connection refused error. So by having TCP post sock created after UDP socket creation it solves issue,
and that the server doesnt send compression results until it has finished receiving packets from client.


Code Issues
--------------
An issue with my code is specifically with the client-server code as in my client code
(severalsockets.c) where I kept my old low entropy UDP packet making in my code 
even though it isnt used anywhere or sent at all, all it does it take up memory. When
I try to removed my old udp packet making from the code, it would make the whole code
work incorrectly as when running client and server, the client would send all data
and reach the point of waiting for TCP post report. While the server would still be 
hanging and waiting for client to send high entropy data when it has already been sent.
I am unsure why this causes this issue to make the code have better integrity I have decided 
to keep my old udp packet making in even though it isnt sent and only takes up data.

I have then fixed the issue using a sleep(5); in order to make sure that the server and client
are sync correctly to receive and send packets at roughly the same point of time. the sleep is put right
before the low entropy packet making.
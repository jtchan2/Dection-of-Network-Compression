Team Members:
Aaron Brion, Justin Chan

(2) COmpiling and running code

Before compiling code, make sure to include correct items in the config files and for ip address, use the the virtual machine's ipv4 addresses

How to compile code for compiling code you would need to do:
1. gcc cJSON.c severalsocketsServer.c -o severalsocketsServer -lm

2.gcc cJSON.c severalsockets -o severalsockets -lm

commands into your terminal, make sure to have both cJSON.h and cJSON.c in directory as it the the API parser used for parsing the json files


To run code you would first do: ./severalsocketServer configserve.json
 on your server VM or machine then you do: ./severalsocket config.json 
on your client vm or machine 

(3) Incomplete/ explanation
In my code there is on error where the client UDP packet sending finishes before server receiving has completed so that the client is waiting for a reponse from server. TO fix, jsut cntrlC and run code again, it will run fine where server recieves around same time client receives.

Design choice:
I have moved the socket creating for post TCP right after UDP port bidning to ensure that when the client finishes sending packets to the server, it can connect to a TCP port and wait to receive infomation instead of hitting a connection refused error for when it would try to connect before post TCP socket would be created.

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char *argv[]){  
    if(argc != 2){
        fprintf(stderr, "Usage: %s <target_server>\n", argv[0]);
        exit(-EINVAL);
    }
    char *target = argv[1];

    
    return 0;
}
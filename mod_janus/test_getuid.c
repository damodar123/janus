
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
    int sd;
    char * argv[3];
    char * prog = strdup("/home/talg/cvs/fcap/test_getuid");
    int i = 7;
    struct sockaddr_in sa; 

    bzero(&sa,sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = 2500;
             

    while (i--) {
            sd = socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
            printf("opened a socket(%d,%d,%d) with fd%d\n",
                PF_INET,SOCK_DGRAM,IPPROTO_IP,sd);
            bind(sd,&sa,sizeof(struct sockaddr_in));
            
            printf("CALLED bind(%d,",sd);
                    printf("%s",inet_ntoa(sa.sin_addr));
                    printf(",%d)\n",sizeof(struct sockaddr_in));

            sd = socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
            printf("opened a socket(%d,%d,%d) with fd%d\n",
                PF_INET,SOCK_DGRAM,IPPROTO_IP,sd);

            connect(sd,&sa,sizeof(struct sockaddr_in));

            printf("CALLED connect(%d,",sd);
                    printf("%s",inet_ntoa(sa.sin_addr));
                    printf(",%d)\n", sizeof(struct sockaddr_in));



            sleep(3);
            close(sd);
    }

    puts("and now O exec");

    argv[0] = strdup("/home/talg/cvs/fcap/test_getuid");
    argv[1] = NULL;

    execv(prog,argv);

    puts("exec err");
    exit(1);
}

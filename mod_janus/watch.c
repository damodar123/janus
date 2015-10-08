
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/net.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fcap.h"
#include "callnames.h"

#define REQUEST_SIZE 2

#define PID 0
#define NUM 1

const int MAX_STR = PAGE_SIZE;


int main(int argc, char * argv[])
{
        int ret;
        int req_num; 
        int i;
        int top_arg = atoi(argv[1]);

        char str[PAGE_SIZE];

        monitor_t watch_this;   
        fd_set wait_set;        /* who we are waiting for events on */

        trap_set enter_set;        
        trap_set exit_set;        
        request_t new_request;      /* what they want to do now */

        pid_t watched1 = atoi(argv[2]); /* who are we watching */

      

        TRAP_ZERO(&enter_set);
        TRAP_ZERO(&exit_set);

        

        for (i = 0; i < top_arg; i++) 
                TRAP_SET(i,&enter_set); 

        /* open syscall for /dev/fcap */
        ret = create_monitor("/dev/fcap");

        if (ret < 0) {
                perror("encountered an error opening /dev/fcap");
                exit(1);
        }
        
        watch_this = ret;


        /* init select stuff */

        FD_ZERO(&wait_set);

        ret = bind_monitor(watch_this,watched1,enter_set,exit_set);

        if (ret < 0) {
              perror("bind_m");  
              exit(1);
        }

        
        puts("starting watch");
        
        printf("watching %d\n",watched1);

        req_num = 0;

        while (1) {
                FD_SET(watch_this,&wait_set);

                select(watch_this + 1,&wait_set,NULL,NULL,NULL);

                ret = read_request(watch_this,&new_request); 
        
                if (ret != sizeof(request_t)) {
                      perror("block");  
                      exit(1);
                }

                //process death
                if (new_request.event_type == EVENT_PROC_DIED) {
                        FD_CLR(watched1,&wait_set);
                        printf(">>>>>>%d now dead!!\n",new_request.pid);
                        exit(0);
                //call exit
                } else if (new_request.event_type == EVENT_CALL_EXIT) {
                        printf("<%d, %s> exited %d\n",new_request.pid,
                                CALL_STR(CALL_NUM(new_request.regs)), 
                                new_request.return_value);

                    if (CALL_NUM(new_request.regs) == SYS_socketcall) {
                        struct fcap_socket_info si;

                        printf("creating new socket: %d\n", 
                            new_request.return_value);
                        fcap_fetchmeta(watch_this, FCAP_SOCK_INFO,
                            &new_request.return_value,&si,sizeof(struct fcap_socket_info));

                        printf("WITH TYPE: %d\n",si.type);
                    }
                //call entry
                } else {
                    printf("<%d, %s,%d>\n",new_request.pid,
                                CALL_STR(CALL_NUM(new_request.regs)),
                                CALL_NUM(new_request.regs));


                    if (CALL_NUM(new_request.regs) == SYS_open) {
                        fcap_fetcharg(watch_this,0,str,MAX_STR,TYPE_PATH);   
                        printf("opening %s\n",str); 

                    }
                    
                    if (CALL_NUM(new_request.regs) == SYS_execve) {
                        fcap_fetcharg(watch_this,0,str,MAX_STR,TYPE_PATH);   
                        printf("execing %s\n",str); 

                    }
                    
                    if (CALL_NUM(new_request.regs) == SYS_socketcall) {
                        int a,b,c;

                        if (new_request.regs.ebx == SYS_SOCKET) {
                            int err; 
                            err = fcap_fetcharg(watch_this,0,&a,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));
                            err = fcap_fetcharg(watch_this,1,&b,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));
                            err = fcap_fetcharg(watch_this,2,&c,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));
                            printf("CALLED socket(%d,%d,%d)\n",a,b,c);

                        } else if (new_request.regs.ebx == SYS_BIND) {
                            int err; 
                            struct sockaddr_in sa;

                            err = fcap_fetcharg(watch_this,0,&a,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));
                            
                            err = fcap_fetcharg(watch_this,1,&sa,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));


                            err = fcap_fetcharg(watch_this,2,&c,sizeof(int),TYPE_SCALAR);   
                            if (err) puts(strerror(err));

                            printf("CALLED bind(%d,",a);
                            printf("%s",inet_ntoa(sa.sin_addr));
                            printf(",%d)\n",c);

                        } else if (new_request.regs.ebx == SYS_CONNECT) {
                        }
                    }


                }

                action_monitor(watch_this,CALL_ALLOW);
        }
        
        destroy_monitor(watch_this);
        
        return 0;
}




/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef _FCAP_H
#define _FCAP_H

#include <linux/ptrace.h>
#include <linux/types.h>
#include <sys/user.h>


/*******************

fcap device interface

This library defines the interface to an fcap device. This device
provides the functionality for process tracing/application
confinement purposes. 

This device and library are part of the Janus package.

Please note that you can trace a particular process with
either fcap or ptrace but not both. Once a process is being
monitored by fcap, ptrace will not be allowed to operate on
that process conversly once a process is ptraced fcap will
not allow you to monitor it (i.e. whoever gets there first 
wins).


Basic model:

With each process we wish to confine we associate a monitor. 

-creating a monitor

A monitor is created with the create_monitor call. We cannot 
do anything with that monitor until we bind it to a process.
If you try EPERM typically EPERM will be returned.

-binding a monitor.

If we would like to confine a process (that is, check the entry
and exit of some of its system calls) we must bind a monitor
to that process. To decide what system calls we will trap
we give two trap_sets (just like fd sets) to the bind call

like so,

bind_monitor(the_monitor, watch_me,enter_mask,exit_mask);

enter_mask: specifies which call entries to trap
exit_mask: specifies which call exits to trap. 

Note that except for fork trapping a call exit is 
rarely useful for confinement.

Once a monitor is bound to a process it cannot be unbound,
if the monitor is closed the process will be killed.

Note that a from our perspective a monitor basically just a file descriptor.

-waiting for events

Once a process is being monitored it will generate an event on
the monitor when the following occur.

1) a system call entry is trapped
2) a system call exit is trapped
3) the process dies.

To wait for these events use the select or poll call with
the file descriptor(s) for your monitor.

-reading events

Once an event has occured you would like to find out
what happend, you can do this as follows

read_request(wait_on_me, event)

note that read_request will return successfully only
if an event is pending, it will not block!

The event (of type request_t) will tell you,

*the event type: (system call entry,exit), process death.

*the pid of the monitored process

*the registers of the process when the event occured
(for system entry and exit events only!!!), 
 from which you can get the system call number, 
 scalar arguments, etc. 

*the return value of the system call for system exit events.


-interpreting events, telling the monitor what to do.

If a process is trapped due to system call entry or exit it
will be placed into an uninterruptible state until such time
as we tell the monitor how to proceded.

this is done with the action_monitor() call.

For system call entry we may

ALLOW_EVENT -- this will allow the call to procede, if
               exit is not trapped the monitored process will
               continue to run as normal.

DENY_EVENT -- this will cause the system call to return EPERM
              to the monitored process, and not preform the system
              call.
              
KILL_PROC -- this will not preform the system call and will kill
             the process with a SIGKILL.

For system call exit we may.

ALLOW_EVENT -- this will allow the get the normal return value of
               the system call and procede as normal.

DENY_EVENT -- this will cause the process to get EPERM
              returned and procede as normal.

KILL_PROC -- this will kill the process with a SIGKILL.


We cannot do anything intresting about process death events,
if a monitored process dies simply call destroy_monitor(or 
close) to free the monitor.

System call exit events are most useful in the case of the
fork() call. See the NOTE below on Strict Fork ordering
and the NOTE in action_monitor about fork for more on this.

-reading system call arguments

see fetchargs()


-reading useful data from the monitored process.

see fetchmeta







***************/



/* Maximum number of monitors that can be open concurrently */
#define MAX_MONITORS 1024


/* trap sets are basically fd_sets that are used to indicate which
system calls to trap the entry and exit of */

/* TRAP_SET TYPE -- for bind_monitor() */
//used to specify which system calls to trap.

#ifndef TRAP_SETS
#define TRAP_SETS

typedef fd_set trap_set;

#define	TRAP_SET(fd, fdsetp)	__FD_SET ((fd), (fdsetp))
#define	TRAP_CLR(fd, fdsetp)	__FD_CLR ((fd), (fdsetp))
#define	TRAP_ISSET(fd, fdsetp)	__FD_ISSET ((fd), (fdsetp))
#define	TRAP_ZERO(fdsetp)		__FD_ZERO (fdsetp)

#endif 



/* REQUEST/EVENT TYPE -- for request_event() */


/* A monitored process can trap on the following events */ 

#define EVENT_CALL_ENTER 1      //trapped a system call entry
#define EVENT_CALL_EXIT 2       //trapped a system call exit
#define EVENT_PROC_DIED 3       //the process we were watching died


extern inline const char *  EVENT_STR(int x)
{
    const char * event_str[] = {"","CALL_ENTER","CALL_EXIT","PROC_DIED"};
    return event_str[x];
}
    
extern inline int CALL_NUM(struct pt_regs regs) { return regs.eax; }



typedef struct __request {
        unsigned int pid;               //who generated the event
        unsigned int event_type;        //what happened
        int return_value;               //if the event was an exit event what
                                        //got returned
                                                                
        struct pt_regs regs;            //the user registers when the event
                                        //was generated (has the arguments to
                                        //the system call) 

} request_t;


/* ACTION TYPES -- for action_monitor */

/* These are the actions a trapped process can take */

enum {CALL_ALLOW,              //allow the current request
      KILL_PROC,               //kill the waiting process
      CALL_DENY                //return EPERM to the waiting process
      };

#define VALID_ACTION_P(x) (((x) >= CALL_ALLOW) && ((x) <= CALL_DENY))



/* METADATA TYPES -- for fetchmeta */

#define FCAP_SOCK_INFO 0

struct fcap_socket_info {
    int type;
};

#define FCAP_FD_INFO 1

struct fcap_fd_info {
    int flags; 
};




/* ARGUMENT TYPES -- for fetcharg() */

#define TYPE_SCALAR 1
#define TYPE_POINTER 2
#define TYPE_STRING 3 
#define TYPE_PATH 4 
#define TYPE_PATH_FOLLOW 5 
#define TYPE_PATH_NOFOLLOW 6
#define TYPE_SOCKADDR 7

/* gid_t sucks because it is an unsigned short in the kernel 
and an int in user land, glibc does the conversion to make
this seem sane. Instead of doing this I just use a new
type that is the same size in both locations */

typedef __kernel_gid_t janus_gid_t;

#ifndef __KERNEL__   /**** Strictly user level stuff ****/



/* used to define what calls you want to trap, familiar interface :) */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/select.h> /* fd_sets */


/*NOTE: select,poll and blocking.

Monitor descriptors are mostly like normal file descriptors 
with except for two features.

1) They will not allow blocking reads i.e. you cannot block
   in request event.

2) if you try to select/poll on a descriptor which has 
   not been bound EPERM will be returned.

*/

/* NOTE: Race free confinement of child processes with strict fork ordering.
   
   Any time a monitored process traps fork() its
   newly created child will be allowed to start running 
   only after the parent resumes running. This is very
   useful as it allows the new child to have a monitor
   bound to it in a race free fasion.

*/

typedef int monitor_t;
typedef int action_t;

/* create_monitor
purpose: create a monitor, what is returned is a normal file
         descriptor. Once you have a monitor you need to 
         bind it to a process in order to do anything
         intresting.

return value: 
         zero   -- An error occured, check errno.
         positive integer -- success.
         
errors: ENOMEM -- there was not enough memory to create a new monitor.
        ENOSPC -- the maximum number of monitors has been reached.
*/

int create_monitor(const char * watch_device);

/* bind_monitor()

purpose: attach a monitor to a given process in order to trap
         system call entry events specified by enter_mask, 
         system call exit events specified by exit_mask,
         process death. 

return value:
            0 -- success.
            -1 -- error.

errors:
            ESRCH -- could not find process watchme to bind to.

            EINVAL -- cound not copy arguments(i.e. one 
                      of the args was invalid.

            EBADSLT -- a trap was requested which 
                       is not supported, (right now
                       you cannot trap SYS_sigreturn 
                       or SYS_rt_sigsuspend.

            EACCES -- tried to bind to a process 
                      which we are not allowed access
                      to (not permissions are the same
                      as ptrace at this time).

            EBADR -- tried to bind a monitor which
                     is already bound.

            EBUSY -- tried to bind to a process that
                     is being ptraced.

            EDEADLK -- tried to bind a process which
                       is already bound by another monitor.

            ENOSPC -- out of space for monitors.

            EPERM -- current process tried to bind itself.


*/
                 
int bind_monitor(monitor_t the_monitor, unsigned int watch_me, 
    trap_set enter_mask,trap_set exit_mask);

/* destroy monitor()

purpose: closes a monitor, kill's any process associated with
         that monitor.

return: 
      0 is returned, this call always succeeds.

errors:
     none.
*/

int destroy_monitor(monitor_t destroy_me);

/* read_request

purpose: Try to read a pending event (System call entry, System call Exit, 
         process death). Note that read_request is strictly non-blocking.

return: -1 -- error
        sizeof(request_t) --  success

errors:
        EWOULDBLOCK -- no event was pending.

        EINVAL -- bad pointer passed, unable to store 
                  request(or bad size passed, this
                  indicates a problem in libfcap).
        
        EPERM -- tried to read on unattached monitor.

         
*/
int read_request(monitor_t wait_on_me, request_t * req);


/* action_monitor()

purpose: when a process event occurs(trapped call entry or exit, 
        process death). The monitored process goes into an uninterupptible
        suspended state. In order to tell it what to do next (abort 
        the system call entry, abort the system call return, 
        kill the process). We use action monitor. 

SPECIAL NOTE ON FORK:
    if a process is currently trapped in a fork exit event its
    new child will not be allowed to run until the process
    is untrapped with an action_monitor call.
    
    if ALLOW_EVENT is specified then the child will be
    allowed to run, otherwise it will be killed.

returns: positive int -- success
         -1  -- error

errors:
      EPERM -- called action on unattached monitor.
      ESRCH -- process associated with monitor not found (i.e. its
               probably died).
      EWOULDBLOCK -- No process currrently waiting for a next_action 
                     (i.e. it only makes sense to tell a monitor
                      its next action if there is something to do).
      EBADRQC -- invalid action type give.
      EINVAL -- error reading the action into the kernel. 

*/

int action_monitor(monitor_t wait_on_me,action_t this_action);


/* fcap_fetcharg()

   purpose: copies a arguments from an argument buffer in kernel
            space to dest. This allows race free checking
            of system call arguments as well as doing
            pleasant things like getting path names
            with symlinks expanded and cannonicalization
            done by the kernel.
            
            -arg should indicate the argument number in
             as given by the standard prototype. For
             example in sendto(..)

             arg = 0 would denote the descriptor etc.

            -size should give the size of the destination, if
             the size of the argument in the kernel exceeds size
             an error will be returned and nothing will be stored in
             dest.
            
            -type indicates the type of the argument being requested,
             fcap will only return arguments of a valid type for
             the given call.

            TYPE_SCALAR - stores a scalar argument in dest.
            TYPE_POINTER - stores a buffer in dest.
            TYPE_STRING - stores a string in dest.
                    
             Stores a null terminated path in dest. 

            TYPE_PATH - path is what was given to the syscall.
            TYPE_PATH_FOLLOW -    path is in absolute form with symlinks expanded.
            TYPE_PATH_NOFOLLOW -  path is in absolute path form with 
                                  symlinks not expanded.
            TYPE_SOCKADDR - a sockaddr is stored in dest. Note this
                            may vary in size.
                    
             -right now fetchargs does not support all
              fetching all non-scalar arguments you might
              wish, (since janus does not need to check 
              all system calls). Fetchargs will only work
              for arguments which are not available as
              scalars in the registers given by a request_t.


return: 0 -- sucess
        -1 -- error

errors:
    EPERM -- tried to fetcharg on unattched monitor.

    EINVAL -- invalid size or dest to given.

    ENODATA -- no argument available for the position and/or type
               you requested.
    

    
*/

int fcap_fetcharg(monitor_t this_monitor,int arg,void * dest,int size,int type);

/* fetchmeta()

purpose: Used to introspect on metadata belonging to the monitored process.
         Currently you may read the types of data, descriptor types,
         and socket types. other metadata may be suppored in the future.
return: 
      0 -- sucess.
      -1 -- error.


errors:
      EBADR -- invalid socket/file descriptor in request.
      EINVAL -- invalid metadata size or problem copying args into kernel.
      EBADRQC -- Invalid metadata type.

*/

int fcap_fetchmeta(monitor_t this_monitor,int type, void * arg, void * dest,
    int size);



#endif 


#endif


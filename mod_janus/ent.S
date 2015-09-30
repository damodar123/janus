#include <linux/linkage.h>
#include <linux/errno.h>
#include "fcap_asm.h"
#define ASSEMBLY

/* offsets into task struct  */
state       =  0
flags       =  4

/*check if current process is being ptraced and if so route it
around our stuff. */

/*
note how I use the return value from fcap_is monitored 
 if %eax == 0 check the call
 if %eax is some error value (where my error vals are > 255) 
 do the right thing(like return -EPERM)
if %eax is non-zero use it as a call number and dispatch
to system call %eax.
pretty filthy...no?
*/

ENTRY(syscall_redirect)
    testb $0x20,flags(%ebx)     # PF_TRACESYS
    jne not_watched
    call SYMBOL_NAME(fcap_is_monitored) #what to do?
    cmpl $ILLEGAL_PTRACE,%eax   
    jne check_entry
    movl $-EPERM,%eax   #no ptracing monitored proc's!
    ret

check_entry:    
    testl %eax,%eax                     
    jnz  not_watched 
    jmp SYMBOL_NAME(fcap_check_call)
not_watched: 
    jmp *SYMBOL_NAME(original_sys_call_table)(,%eax,4)
    


/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

/* handy items for module writing, global_use_count should be defined before */
/* inclusion */
#ifndef MODTOOLS_H
#define MODTOOLS_H

#define TRUE 1
#define FALSE 0

typedef int mybool; 


#if FC_DEBUG > 0
        #define PDEBUG(fmt, ARGS...) printk(KERN_DEBUG "fcap DEBUG >>%d:  " fmt "\n" , ## __LINE__ , ## ARGS)
#else
        #define PDEBUG(fmt,ARGS...)
#endif

#define RETURN(x) do { PDEBUG("%s returned %d",__FUNCTION__,(x)); return (x); } while (0)

/* usage count can be a pain when code is unstable */

#ifndef __NO_VERISON__ 
        static int global_use_count = 0;       
#endif

static inline void ADD_USE_COUNT()
{
    MOD_INC_USE_COUNT;
    global_use_count++;
}

static inline void DEC_USE_COUNT()
{
    MOD_DEC_USE_COUNT;
    global_use_count--;
}


static inline int IN_USE_P()
{
    return MOD_IN_USE;
}

static inline int GLOBAL_USE_COUNT()
{
    return global_use_count;
}

#define PERROR(fmt, ARGS...) printk(KERN_ERR "fcap ERROR %s:%s:%d  " fmt "\n" , ##__FILE__, ## __FUNCTION__ ,## __LINE__ , ## ARGS)
#define PINFO(fmt, ARGS...) printk(KERN_INFO "fcap:  " fmt "\n" , ## ARGS)
#define PNOTE(fmt, ARGS...) printk(KERN_NOTICE "fcap:  " fmt "\n" , ## ARGS)
#define PMSG(level,fmt, ARGS...) printk(level "fcap:  " fmt "\n" , ## ARGS)

#define SLEEP_ON_LIGHT(x) interruptible_sleep_on(x)
#define WAKE_UP_LIGHT(x) wake_up_interruptible(x) 

#define SLEEP_ON_DEEP(x) sleep_on(x)
#define WAKE_UP_DEEP(x) wake_up(x) 

#define UNINITIALIZED -1

static inline int recieved_signal_p() 
{

        int i, is_sig = 0;        

        for(i=0; i<_NSIG_WORDS && !is_sig; i++) {
            is_sig = current->signal.sig[i] & 
                        ~current->blocked.sig[i];

            if (is_sig)
                PDEBUG("%d got signal; signal[%d] = %lX, blocked[%d] = %lX",
                    current->pid, i, current->signal.sig[i],
                    i, current->blocked.sig[i]);

        }

        return is_sig;

}

#define kassert(x)							\
	do { if(!(x))							\
	{								\
		printk(KERN_CRIT "Assertion failed in %s:%d (%s): %s\n",		\
		       __FILE__, __LINE__, __FUNCTION__, #x);		\
	} } while(0)

#endif

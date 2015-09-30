
/*
 * Copyright (c) 2000 The Regents of the University of California.
 *
 * See the file "LICENSE" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */


#ifndef CHILDSTATE_H
#define CHILDSTATE_H

void init_childstate();

int childstate_set_starting_dir(const char * dir);
int childstate_set_starting_uid(const char * user);
int childstate_set_starting_gid(const char * group);
int childstate_set_starting_priority(const char * pri);

int childstate_putrlimit(const char * conf_line);
int childstate_putenv(const char * conf_line);

void childstate_start_child(char * path,char * * argv,int interactive);
#endif

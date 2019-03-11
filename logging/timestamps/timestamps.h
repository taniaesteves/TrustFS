/*
  TrustFS
  Copyright (C) 2019 INESC TEC. Written by T. Esteves, R. Macedo and J. Paulo

  Based on SafeFS project (https://github.com/safecloud-project/safefs) - Copyright (C) 2016 INESC TEC. Written by J. Paulo and R. Pontes
  
  This program can be distributed under the terms of the GNU GPL v3.
  See the file COPYING.
*/


#ifndef __TIMESTAMPS_H__
#define __TIMESTAMPS_H__

void store(GSList** list, struct timeval start, struct timeval stop);

void print_latencies(GSList* list, char* driver, char* op);

#endif /* __XOR_H__ */

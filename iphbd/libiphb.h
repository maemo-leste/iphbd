/**
   @brief This is the interface to IP heartbeat service (via libiphb).

   @file libiphb.h

   This is the interface to IP heartbeat service (via libiphb).

   <p>
   Copyright (C) 2008 Nokia. All rights reserved.

*/




#ifndef IPHB_H
#define IPHB_H

#include <time.h>

/**
   Handle to IP heartbeat service (NULL is invalid handle) 
*/
typedef void * iphb_t; 




/**
   IPHBD_DBUS_SERVICE:
   The name of the iphbd service.
*/
#define IPHBD_DBUS_SERVICE "com.nokia.iphbd"

/**
   IPHBD_DBUS_PATH:
   The object path for the iphbd daemon.
*/
#define IPHBD_DBUS_PATH "/com/nokia/iphbd"

/**
   IPHBD_DBUS_INTERFACE:
   The interface the commands use.
*/
#define IPHBD_DBUS_INTERFACE "com.nokia.iphbd"


/**
   IPHBD_DBUS_WAKEUP:
   Signal from iphbd when the heartbeat occurs (PID appended!).
   Data is int32 (current time)

*/
#define IPHBD_DBUS_WAKEUP     "wakeup"



/**
   IPHB_DBUS_MATCH_RULE:
   Rule for dbus_bus_add_match to match heartbeats.<br>
   Use snprintf to create your own rule as follows:<br>
     snprintf(rule, sizeof(rule), IPHB_DBUS_MATCH_RULE, iphb_get_uid(h));

*/
#define IPHB_DBUS_MATCH_RULE "type='signal',interface='com.nokia.iphbd',member='wakeup%lu'"






/**
   Open iphb service.

   @param heartbeat_interval   Returned TCP/IP keepalive period (systyem setting); this is "FYI".

   @return	handle for iphb, NULL if error (check errno). 
                If error, behave just like before (i.e. no heartbeat service)

*/   

iphb_t iphb_open(int *heartbeat_interval);









/**
   Wait for the next heartbeat. 


   @param iphbh		Handle got from iphb_open
   @param mintime	Time in seconds that MUST be waited before heartbeat is reacted to.
                        Value 0 means 'wake me up when someboy else is woken'
   @param maxtime	Time in seconds when the wait MUST end. It is wise to have maxtime-mintime quite big so all users of this service get synced.
   @param must_wait	1 if this functions waits for heartbeat, 0 if you are going to use select/poll (see iphb_get_fd) 
                        or D-Bus signal (see IPHBD_DBUS*)

   @return		Time waited, (time_t)-1 if error (check errno)


*/
time_t
iphb_wait(iphb_t iphbh, unsigned short mintime, unsigned short maxtime, int must_wait);






/**
   Get file descriptor for iphb (for use with select()/poll())

   @param iphbh	Handle got from iphb_open

   @return	Descriptor that can be used for select/poll, -1 if error (check errno)
*/   

int iphb_get_fd(iphb_t iphbh);




/**
   Get unique connection ID (to construct D-Bus filter)

   @param iphbh	Handle got from iphb_open

   @return	ID for the connection (> 0), 0 if error (check errno)
*/   

unsigned long iphb_get_uid(iphb_t iphbh);



/** iphbd statistics
   - unsigned int clients: number of active IPHB clients
   - unsigned int waiting: number of IPHB clients that are waiting for heartbeat
   - unsigned int next_hb: number of seconds after the next heartbeat shall occur, 0 if there are nobody waiting 
*/

struct iphb_stats {
  unsigned int     clients;  
  unsigned int 	   waiting; 	
  unsigned int     next_hb; 	
};


/**
   Get statistics. Struct iphb_stats is filled as follows:<br>
   - unsigned int clients: number of active IPHB clients
   - unsigned int waiting: number of IPHB clients that are waiting for heartbeat
   - unsigned int next_hb: number of seconds after the next heartbeat shall occur, 0 if there are nobody waiting 


   @param iphbh	Handle got from iphb_open
   @param stats Statistics placeholder (filled when success)

   @return	0 if OK, -1 if error (check errno)
*/   

int iphb_get_stats(iphb_t iphbh, struct iphb_stats *stats);





/**
   Close iphb service.

   @param iphbh	Handle got from iphb_subscribe

   @return	NULL always (so it is nice to set local handle to NULL)
*/   
iphb_t iphb_close(iphb_t iphbh);



#endif  /* IPHB_H */


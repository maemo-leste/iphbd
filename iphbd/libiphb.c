/**
   @brief Implementation of libiphb

   @file libiphb.c

   Implementation of libiphb (see libiphb.h)

   <p>
   Copyright (C) 2008-2010 Nokia Corporation.

   @author Raimo Vuonnala <raimo.vuonnala@nokia.com>
   @author Semi Malinen <semi.malinen@nokia.com>

   This file is part of Dsme.

   Dsme is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License
   version 2.1 as published by the Free Software Foundation.

   Dsme is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with Dsme.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
/* socket transport */
#include <sys/socket.h>
#include <sys/un.h>
/* --- */

#include "libiphb.h"
#include "iphb_internal.h"

/**@brief  Allocated structure for handle to iphbd */
struct _iphb_t {
  /*!< Unix domain socket handle */
  int fd;
  /*!< iphbd client id */
  unsigned long uid;
};

#define HB_INST(x) ((struct _iphb_t *) (x))

iphb_t
iphb_close(iphb_t iphbh)
{
  if (iphbh)
  {
    close(HB_INST(iphbh)->fd);
    HB_INST(iphbh)->fd = 0;
    free(iphbh);
  }

  return NULL;
}

iphb_t
iphb_open(int *heartbeat_interval)
{
  iphb_t iphbh;
  int fd;

  iphbh = malloc(sizeof(struct _iphb_t));
  if (!iphbh)
  {
    errno = -ENOMEM;
    return NULL;
  }

  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (fd >= 0)
  {
    struct sockaddr_un addr;

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, HB_SOCKET_PATH);

    if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
    {
      struct _iphb_open_resp_t resp;

      if (recv(fd, &resp, sizeof(resp), MSG_WAITALL) > 0)
      {
        if (heartbeat_interval)
          *heartbeat_interval = resp.timeout;

        HB_INST(iphbh)->fd = fd;
        HB_INST(iphbh)->uid = resp.uid;
        return iphbh;
      }
    }

    close(fd);
  }

  free(iphbh);

  return NULL;
}

int
iphb_get_fd(iphb_t iphbh)
{
  if (!iphbh)
  {
    errno = -EINVAL;
    return 0;
  }

  return HB_INST(iphbh)->fd;
}

unsigned long
iphb_get_uid(iphb_t iphbh)
{
  if (!iphbh)
  {
    errno = -EINVAL;
    return 0;
  }

  return HB_INST(iphbh)->uid;
}

static int
suck_data(int fd)
{
  int32_t bytes = -1;

  /* suck away unread messages */
  if (ioctl(fd, FIONREAD, &bytes) != -1 && bytes > 0)
  {
    if (bytes)
    {
      char *b = (char *)malloc(bytes);

      if (!b)
      {
        errno = ENOMEM;
        return -1;
      }

      (void)recv(fd, b, bytes, MSG_WAITALL);
      free(b);
    }
  }

  return 0;
}

int
iphb_get_stats(iphb_t iphbh, struct iphb_stats *stats)
{
  struct _iphb_req_t req;
  int st;

  memset(&req, 0, sizeof(req));
  req.cmd = IPHB_STAT;

  if (!iphbh)
  {
    errno = -EINVAL;
    return -1;
  }

  st = suck_data(HB_INST(iphbh)->fd);
  if (st)
    return st;

  st = send(HB_INST(iphbh)->fd, &req, sizeof(req), MSG_DONTWAIT | MSG_NOSIGNAL);
  if (st <= 0)
    return -1;

  if (recv(HB_INST(iphbh)->fd, stats, sizeof(*stats), MSG_WAITALL) > 0)
      return 0;

  return -1;
}

time_t
iphb_wait(iphb_t iphbh, unsigned short mintime, unsigned short maxtime,
          int must_wait)
{
  struct _iphb_req_t req = {IPHB_WAIT};
  struct _iphb_wait_resp_t resp = {0};
  int st;

  if (!iphbh || mintime > maxtime)
  {
    errno = EINVAL;
    return (time_t)-1;
  }

  st = suck_data(HB_INST(iphbh)->fd);
  if (st)
    return (time_t)-1;

  req.u.wait.mintime = mintime;
  req.u.wait.maxtime = maxtime;
  req.u.wait.pid = getpid();

  st = send(HB_INST(iphbh)->fd, &req, sizeof(req), MSG_DONTWAIT | MSG_NOSIGNAL);
  if (st <= 0)
    return (time_t)-1;

  if (!must_wait)
    return (time_t)0;

  if (maxtime)
  {
    fd_set readfds;
    struct timeval timeout;
    time_t then = time(0);
    time_t now;

    timeout.tv_sec = maxtime;
    timeout.tv_usec = 0;

    for (;;) {
      FD_ZERO(&readfds);
      FD_SET(HB_INST(iphbh)->fd, &readfds);
      st = select(HB_INST(iphbh)->fd + 1, &readfds, NULL, NULL, &timeout);
      now = time(0);

      if (st == -1 && errno == EINTR)
      {
        if (now - then < maxtime)
        {
          timeout.tv_sec = maxtime - (now - then);
          continue;
        }
      }

      break;
    }

    if (st == 0) /* timeout */
      return now - then;
  }

  if (recv(HB_INST(iphbh)->fd, &resp, sizeof(resp), MSG_WAITALL) > 0)
    return resp.waited;
  else
    return (time_t)-1;
}

int
iphb_I_woke_up(iphb_t iphbh)
{
  int st;
  struct _iphb_req_t req = {IPHB_WAIT};

  if (!iphbh)
  {
    errno = EINVAL;
    return -1;
  }

  st = suck_data(HB_INST(iphbh)->fd);

  if (st)
    return st;

  req.u.wait.pid = getpid();
  req.u.wait.mintime = 0;
  req.u.wait.maxtime = 0;

  if (send(HB_INST(iphbh)->fd, &req, sizeof(req), MSG_DONTWAIT|MSG_NOSIGNAL) !=
      sizeof(req))
  {
    return -1;
  }

  return 0;
}

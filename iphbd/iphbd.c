#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>

#include <dbus/dbus.h>

/* socket transport */
#include <sys/socket.h>
#include <sys/un.h>

#include "libiphb.h"
#include "iphb_internal.h"

#define IPHBD_CRITICAL(msg, ...) do {\
  if (debug) {printf("iphb:"msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);}\
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_CRIT), msg, ##__VA_ARGS__); \
  } while(0)

#define IPHBD_ERROR(msg, ...) do {\
  if (debug) {printf("iphb:"msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);} \
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_ERR), msg, ##__VA_ARGS__); \
} while(0)

#define IPHBD_WARNING(msg, ...) do {\
  if (debug) {printf(msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);} \
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_WARNING), msg, ##__VA_ARGS__); \
  } while(0)

#define IPHBD_NOTICE(msg, ...)  do {\
  if (debug) {printf(msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);} \
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_NOTICE), msg, ##__VA_ARGS__); \
  } while(0)

#define IPHBD_INFO(msg, ...)  do {\
  if (debug) {printf("iphb:"msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);}\
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_INFO), msg, ##__VA_ARGS__); \
} while(0)

#define IPHBD_DEBUG(msg, ...) do {\
  if (debug) {printf(msg, ##__VA_ARGS__); putchar(0x0a); fflush(stdout);\
  syslog(LOG_MAKEPRI(LOG_KERN, LOG_DEBUG), msg, ##__VA_ARGS__); \
  }} while(0)

typedef struct _client_t
{
  int fd;
  time_t wait_started;
  unsigned short mintime;
  unsigned short maxtime;
  unsigned long uid;
  pid_t pid;
  struct _client_t *next;
} client_t;

static bool run = true;
static int kernelfd = -1;
static int listenfd = -1;
static bool debug = false;
static bool noop_test_mode = false;
static bool simple_mode = false;
static bool keepalive_queue_disable = false;
static bool kernel_signal_wake = true;
static int heartbeat_interval = 30;
static unsigned long uid = 1;
static bool sighup = false;
static client_t *clients = NULL;
static DBusConnection *bus = NULL;

#define IPHBD_MAX_CLIENTS 512

static void kernel_socket_open(void)
{
  static int kernel_module_load_error_logged = 0;

  if (!keepalive_queue_disable)
  {
    kernelfd = open(HB_KERNEL_DEVICE, O_RDWR, 0644);

    if (kernelfd == -1)
      kernelfd = open(HB_KERNEL_DEVICE_TEST, O_RDWR, 0644);

    if (kernelfd == -1)
    {
      if (!kernel_module_load_error_logged)
      {
        kernel_module_load_error_logged = 1;
        IPHBD_ERROR("failed to open kernel connection '%s' (%s)",
                    HB_KERNEL_DEVICE, strerror(errno));
      }
    }
    else
    {
      const char *msg = HB_LKM_KICK_ME_PERIOD;

      IPHBD_DEBUG("opened kernel socket %d to %s, wakeup from kernel=%s",
                  kernelfd, HB_KERNEL_DEVICE, HB_LKM_KICK_ME_PERIOD);

      if (write(kernelfd, msg, strlen(msg) + 1) == -1)
        IPHBD_ERROR("failed to write kernel message (%s)", strerror(errno));
    }
  }
}

static void iphb_shutdown()
{
  client_t *c = clients;
  client_t *prev = NULL;

  IPHBD_INFO("shutting down");

  while (c)
  {
    close(c->fd);
    prev = c;
    c = c->next;
    free(prev);
  }

  if (listenfd != -1)
    close(listenfd);

  if (kernelfd != -1)
    close(kernelfd);

  if (bus)
  {
    dbus_connection_unref(bus);
    bus = NULL;
  }
}

void
usage(const char *name)
{
          printf("%s [-h] [-d] [-w] [interval]\n", name);
          puts("   -h: print this help");
          puts("   -d: enable debugmode");
          puts("   -a: enable advanced mode");
          puts("   -k: disable TCP keepalive queuing");
          puts("   -w: wake from kernel signal (TCP queuing must be enabled)");
          printf(
            "   interval is the heartbeat in seconds (default %d), minumum is 3 secs, value -1 means that no sync is done\n",
            30);
}

void
signal_handler(int signum)
{
  switch (signum)
  {
    case SIGHUP:
      sighup = true;
      break;
    case SIGINT:
    case SIGTERM:
      run = false;
      IPHBD_INFO("got kill");
      break;
    case SIGUSR1:
      IPHBD_INFO("changed debugmode to %s", !debug ? "DEBUG" : "nodebug");
      debug = !debug;
      break;
    case SIGUSR2:
      simple_mode = !simple_mode;
      IPHBD_INFO("mode changed to %s", simple_mode ? "simple" : "complex");
      break;
    default:
      IPHBD_WARNING("got strange signal %d", signum);
      break;
  }

  if (run)
    signal(signum, signal_handler);
}

static int
wait_events(struct pollfd *pfds, nfds_t *nfds, time_t now)
{
  client_t *c = clients;
  int nc = 0;
  int sleeptime = 60;
  struct pollfd *fds = pfds;

  IPHBD_DEBUG("waiting events...");

  fds[0].fd = listenfd;
  fds[0].events = POLLIN;

  if (kernelfd != -1)
  {
    fds[1].fd = kernelfd;
    fds[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    *nfds = 2;
  }
  else
    *nfds = 1;

  fds = &fds[*nfds];

  for (c = clients; c && *nfds < IPHBD_MAX_CLIENTS; c = c->next,
       (*nfds)++, nc++, fds++)
  {
    fds->fd = c->fd;
    fds->events = POLLIN | POLLERR | POLLHUP | POLLNVAL | POLLRDHUP;

    if (c->wait_started)
    {
      int maxtime = simple_mode ? heartbeat_interval : c->maxtime;
      unsigned long deadline = maxtime + c->wait_started;

      if (deadline < sleeptime + now)
        sleeptime = deadline - now;

      IPHBD_DEBUG("client with socket %d wanted a wakeup-call, it has slept %lu secs - sleeptime now %d",
                  c->fd, now - c->wait_started, sleeptime);
    }
  }

  if (!nc)
    sleeptime = 3600;

  IPHBD_DEBUG("waiting with sleeptime %d, nfds=%lu, clients=%d", sleeptime,
              *nfds, nc);

  return poll(pfds, *nfds, 1000 * sleeptime);
}

static void
add_client(int fd)
{
  client_t *c = (client_t *)calloc(1, sizeof(client_t));
  client_t *next = clients;

  if (!c)
  {
    IPHBD_ERROR("malloc(add_client) failed");
    abort();
  }

  c->fd = fd;
  c->uid = uid;
  uid++;

  if (uid == -1)
    uid = 1;

  if (next)
  {
    while (next->next)
      next = next->next;

    next->next = c;

    IPHBD_DEBUG("added client with socket %d, UID=%lu", fd, c->uid);
  }
  else
    clients = c;

}

static void
accept_client(void)
{
  int fd = accept(listenfd, 0, 0);
  struct _iphb_open_resp_t resp = {heartbeat_interval, uid};

  if (fd == -1)
  {
    IPHBD_ERROR("failed to accept client (%s)", strerror(errno));
    return;
  }

  if (send(fd, &resp, sizeof(resp), MSG_DONTWAIT|MSG_NOSIGNAL) == sizeof(resp))
    add_client(fd);
  else
  {
    IPHBD_ERROR("failed to send to client (%s), drop client", strerror(errno));
    close(fd);
  }
}


static void
remove_client(client_t* client, client_t* prev)
{
    if (prev)
        prev->next = client->next;

    if (client == clients)
        clients = client->next;
}

static client_t *
close_and_free_client(client_t* client)
{
  client_t* c = client->next;

  (void)close(client->fd);
  free(client);

  return c;
}

static client_t *
delete_client(client_t* client)
{
    /* remove the client from the list */
    client_t* prev = 0;
    client_t* c = clients;

    while (c)
    {
        if (client == c)
        {
            remove_client(client, prev);
            break;
        }

        prev = c;
        c = c->next;
    }

    return close_and_free_client(client);
}

static void
handle_wait_req(struct _iphb_wait_req_t *req, client_t *client, time_t now)
{
  if (!req->mintime && !req->maxtime)
  {
    req->mintime = HB_MINTIME(heartbeat_interval);
    req->maxtime = HB_MAXTIME(heartbeat_interval);
  }

  IPHBD_DEBUG("client with socket %d signaled interest of waiting (min=%d/max=%d)",
              client->fd, req->mintime, req->maxtime);

  client->wait_started = now;
  client->maxtime = req->maxtime;
  client->mintime = req->mintime;
  client->pid = req->pid;
}

static void
handle_stats_req(client_t *client)
{
  struct iphb_stats stats;
  client_t *c = clients;
  unsigned int next_hb = 0;
  time_t now = time(0);

  memset(&stats, 0, sizeof(stats));

  while (c)
  {
      stats.clients++;

      if (c->wait_started)
          stats.waiting++;

      if (c->wait_started)
      {
          unsigned int wait_time = c->wait_started + c->maxtime - now;

          if (!next_hb)
              next_hb = wait_time;
          else
          {
              if (wait_time < next_hb)
                  next_hb = wait_time;
          }
      }

      c = c->next;
  }

  stats.next_hb = next_hb;

  if (send(client->fd, &stats, sizeof(stats), MSG_DONTWAIT | MSG_NOSIGNAL) !=
      sizeof(stats))
  {
      IPHBD_ERROR("failed to send to client (%s)", strerror(errno));
  }
}

static struct pollfd *
find_client_pollfd(client_t *client, struct pollfd *fds, nfds_t first,
                   nfds_t nfds)
{
  nfds_t i;

  for (i = first; i < nfds; i++)
  {
    if (client->fd == fds[i].fd)
      return &fds[i];
  }

  return NULL;
}

static void
handle_clients(struct pollfd *fds, nfds_t nfds, time_t now)
{
  client_t *client;
  nfds_t first = (kernelfd == -1 ? 1 : 2);
  struct pollfd *pollfd;
  struct _iphb_req_t req;

  for (client = clients; client ; client = client->next)
  {
    pollfd = find_client_pollfd(client, fds, first, nfds);

    if (!pollfd)
      continue;

    if (!pollfd->revents)
      continue;

    memset(&req, 0, sizeof(req));

    if (pollfd->revents & POLLERR ||
        pollfd->revents & POLLRDHUP ||
        pollfd->revents & POLLHUP)
    {
      IPHBD_ERROR("client with socket %d disappeared", client->fd);
      client = delete_client(client);
    }
    else
    {
      IPHBD_DEBUG("client with socket %d is active, revents=%x", client->fd,
                  pollfd->revents);

      if (recv(client->fd, &req, sizeof(req), MSG_WAITALL) > 0)
      {
        if (req.cmd == IPHB_WAIT)
          handle_wait_req(&req.u.wait, client, now);
        else if (req.cmd == IPHB_STAT)
          handle_stats_req(client);
        else
        {
          IPHBD_ERROR("client with socket %d, uid %lu, gave invalid command, drop it",
                      client->fd, client->uid);
          client = delete_client(client);
        }
      }
      else
      {
        IPHBD_ERROR("failed to read from client with socket %d, uid %lu (%s), dropping client",
                    client->fd, client->uid, strerror(errno));
        client = delete_client(client);
      }
    }

    if (!client)
      break;
  }
}

static bool
mintime_passed(client_t* client, time_t now)
{
  return now >= client->wait_started + client->mintime;
}

static bool
maxtime_passed(client_t* client, time_t now)
{
  return now >= client->wait_started + client->maxtime;
}

static bool
wake_up_client(client_t *client, time_t now)
{
  struct _iphb_wait_resp_t resp;
  DBusMessage *msg;
  char buf[100];

  resp.waited = now - client->wait_started;
  client->wait_started = 0;

  IPHBD_DEBUG(">>>>>>>>>>>> waking up client who has slept %d secs with socket %d, UID %lu, PID %lu",
              (int)resp.waited,
              client->fd,
              client->uid,
              (unsigned long)client->pid);

  if (send(client->fd, &resp, sizeof(resp), MSG_DONTWAIT | MSG_NOSIGNAL) !=
      sizeof(resp))
  {
    return false;
  }

  snprintf(buf, sizeof(buf), IPHBD_DBUS_WAKEUP"%lu", client->uid);
  msg = dbus_message_new_signal(IPHBD_DBUS_PATH, IPHBD_DBUS_INTERFACE, buf);

  if (!msg)
    IPHBD_ERROR("dbus_message_new_signal failed");
  else
  {
    int32_t _now = now;

    if (!dbus_message_append_args(msg,
                                  DBUS_TYPE_INT32, &_now,
                                  DBUS_TYPE_INVALID))
    {
      IPHBD_ERROR("dbus_message_append_args failed");
    }
    else
    {
      if (dbus_connection_send(bus, msg, NULL))
        IPHBD_DEBUG("sent D-Bus signal %s", buf);
      else
        IPHBD_ERROR("dbus_connection_send failed");
    }

    dbus_message_unref(msg);
  }

  return true;
}

static int
find_one_to_wake(time_t now)
{
  client_t *client;

  for (client = clients; client; client = client->next)
  {
    if (client->wait_started && now >= maxtime_passed(client, now))
      return 1;
  }

  return -1;
}

static bool
wake_up_clients(time_t now, bool kernel_wakeup, time_t *last_wakeup)
{
  int total_clients;
  client_t *client;
  time_t last_active;
  int client_maxtime_passed;
  int woken;
  bool simple_mode_wake = false;

  IPHBD_DEBUG("waking up clients%s...",
              kernel_wakeup ? " because of network traffic" : "");

  if (!clients)
    return false;

  if (simple_mode)
  {
    if ((now >= *last_wakeup + heartbeat_interval) ||
        (kernel_wakeup && now >= HB_MINTIME(heartbeat_interval) + *last_wakeup))
    {
      IPHBD_DEBUG("waking up all sleeping clients in simple mode, %d secs since last wake-up call",
                  (int)(now - *last_wakeup));

      simple_mode_wake = true;
      *last_wakeup = now;
    }
    else
    {
      IPHBD_DEBUG("no time to wake up sleeping clients in simple mode, %d secs since last wake-up call",
                  (int)(now - *last_wakeup));
    }
  }

  total_clients = 0;

  woken = 0;
  client_maxtime_passed = -1;

  for (client = clients; client; client = client->next)
  {
    total_clients++;

    if (!client->wait_started)
    {
        IPHBD_DEBUG("client with sock %d is active, not to be woken up",
                    client->fd);
      continue;
    }

    IPHBD_DEBUG("client with sock %d, UID %lu, has slept %lu secs", client->fd,
                client->uid, now - client->wait_started);

    if (noop_test_mode)
    {
      if (!maxtime_passed(client, now))
        continue;
    }
    else
    {
      if (!simple_mode)
      {
        if (!((woken && !client->mintime) ||
              (kernel_wakeup &&
               client->mintime &&
               mintime_passed(client, now))))
        {
          if (client_maxtime_passed == -1)
            client_maxtime_passed = find_one_to_wake(now);

          last_active = client->wait_started;

          if (now < client->maxtime + last_active)
          {
            if (client_maxtime_passed != 1 || client->mintime == 0)
              continue;

            if (now < client->mintime + last_active)
              continue;
          }
        }
      }
      else
      {
        if (!simple_mode_wake)
          continue;
      }
    }

    if (wake_up_client(client, now))
      woken++;
    else
    {
      total_clients--;

      IPHBD_ERROR("failed to send to client fd %d, uid %lu, (%s), drop client",
                  client->fd, client->uid, strerror(errno));

      if (!(client = delete_client(client)))
        break;
    }
  }

  IPHBD_DEBUG("woke up %d of total %d clients", woken, total_clients);

  return total_clients;
}

int
main(signed int argc, char **argv)
{
  int i;
  int rv = 2;
  time_t kernel_signal_time;
  struct sockaddr_un addr;
  DBusError dbus_error = DBUS_ERROR_INIT;
  time_t last_wakeup;
  const char *p;

  IPHBD_INFO("starting up");

  for (i = 1; i < argc; i++)
  {
    p = argv[i];

    if (!strcmp(argv[i], "-h"))
    {
      usage(argv[0]);
      return -1;
    }

    if (!strcmp(p, "-d"))
    {
      IPHBD_INFO("started up in debug mode");
      debug = true;
    }
    else if (!strcmp(p, "-k"))
    {
      IPHBD_INFO("TCP keepalive queuing disabled");
      keepalive_queue_disable = true;
    }
    else if (!strcmp(p, "-s"))
    {
      IPHBD_INFO("started up in simple  mode");
      simple_mode = true;
    }
    else if (!strcmp(p, "-w"))
    {
      IPHBD_INFO("do not wake from kernel signal");
      kernel_signal_wake = false;
    }
    else
    {
      heartbeat_interval = atoi(p);;

      if (heartbeat_interval)
      {
        if (heartbeat_interval < 3)
        {
          usage(argv[0]);
          return 1;
        }
      }
      else
      {
        kernel_signal_wake = false;
        simple_mode = false;
        keepalive_queue_disable = true;
        noop_test_mode = true;
        heartbeat_interval = 30;
      }

      IPHBD_INFO("started up with default interval %d %s", heartbeat_interval,
                 noop_test_mode ? "(no-op test mode)" : "");
    }
  }

  signal(SIGHUP, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, signal_handler);

  bus = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);

  if (!bus)
  {
    IPHBD_ERROR("dbus_bus_get() %s", dbus_error.message);
    sleep(5);
    goto out;
  }

  if (dbus_bus_request_name(bus, IPHBD_DBUS_INTERFACE,
                           DBUS_NAME_FLAG_ALLOW_REPLACEMENT, &dbus_error) == -1)
  {
    IPHBD_ERROR("dbus_bus_request_name(%s) error %s", IPHBD_DBUS_INTERFACE,
                dbus_error.message);
    sleep(2);
    goto out;
  }

  listenfd = socket(PF_UNIX, SOCK_STREAM, 0);

  if (listenfd < 0)
  {
    IPHBD_ERROR("failed to open client listen socket (%s)", strerror(errno));
    goto out;
  }

  unlink(HB_SOCKET_PATH);
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, HB_SOCKET_PATH);

  if (bind(listenfd, &addr, sizeof(addr)))
  {
    IPHBD_ERROR("failed to bind client listen socket to %s, (%s)",
                HB_SOCKET_PATH, strerror(errno));
    goto out;
  }

  if (chmod(HB_SOCKET_PATH, 0666u))
  {
    IPHBD_ERROR("failed to chmod '%s' (%s)", HB_SOCKET_PATH, strerror(errno));
    goto out;
  }

  if (listen(listenfd, 5))
  {
    IPHBD_ERROR("failed to listen client socket (%s)", strerror(errno));
    goto out;
  }

  IPHBD_DEBUG("opened client socket %d to %s", listenfd, HB_SOCKET_PATH);

  last_wakeup = time(0);
  kernel_signal_time = last_wakeup;

  while (run)
  {
    time_t now;
    struct pollfd fds[512];
    bool kernel_wakeup;
    nfds_t nfds;
    time_t wait_started_time;
    int st;

    wait_started_time = time(0);
    st = wait_events(fds, &nfds, wait_started_time);

    /* FIXME - what a condition, eh? */
    if (st != -1 || errno != EINTR || sighup)
    {
      kernel_wakeup = false;

      if (sighup)
      {
        kernel_signal_time = wait_started_time;
        sighup = false;
        kernel_wakeup = true;
      }

      now = time(0);

      if (st > 0)
      {
        IPHBD_DEBUG("poll() ready, st = %d", st);

        if (fds[0].revents)
        {
          IPHBD_DEBUG("accept() ready, revents=%x", fds[0].revents);
          accept_client();
        }

        if (kernelfd != -1 && fds[1].revents)
        {
          IPHBD_DEBUG("kernel signal");

          kernel_signal_time = now;

          if (kernel_signal_wake)
            kernel_wakeup = true;
        }

        handle_clients(fds, nfds, now);
      }
      else if (st == -1)
      {
        if (errno != EINTR)
        {
          IPHBD_ERROR("failed to poll (%s)", strerror(errno));
          now++;
          sleep(1);
        }
      }
      else
        IPHBD_DEBUG("poll timeout");

      if (wake_up_clients(now, kernel_wakeup, &last_wakeup))
      {
        if (now >= kernel_signal_time + 60)
        {
          if (kernelfd == -1)
            kernel_socket_open();

          if (kernelfd == -1)
            kernel_signal_time = now;
          else
          {
            IPHBD_DEBUG("signaling kernel...");

            if (write(kernelfd, "F", 2) != -1)
              kernel_signal_time = now;
            else
            {
              IPHBD_ERROR("failed to write kernel message (%s)",
                          strerror(errno));

              close(kernelfd);
              kernelfd = -1;
            }
          }
        }
      }
      else if (kernelfd != -1)
      {
        if (write(kernelfd, "F", 2) == -1)
          IPHBD_ERROR("failed to write kernel message (%s)", strerror(errno));

        IPHBD_DEBUG("closed kernel socket %d", kernelfd);

        close(kernelfd);
        kernelfd = -1;
      }
    }
  }

  rv = 0;

out:
  iphb_shutdown();

  return rv;
}



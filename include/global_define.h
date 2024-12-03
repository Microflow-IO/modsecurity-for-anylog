#ifndef _GLOBAL_DEFINE_H_
#define _GLOBAL_DEFINE_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define  SEND_MODE_GELF                       1
#define  SEND_MODE_SYSLOG                     2

#define  DEFAULT_LISTEN_PORT                  12202
#define  DEFAULT_SEND_PORT                    12202

typedef struct {
  u_int32_t src, dst, forward;
  int sport, dport, ret_code;
  time_t stamp;
  char host[64], source[64], method[64], strTime[64], strClient[64];
  char strServer[64], strForward[64], domain[64], strVersion[64];
  char agent[64], refer[128], cookie[256], request_header[512];
  char response_header[512], message[512], request_body[1024];
  char url[1024], response_body[1024], matched[65536], msg[65536];
} HttpInfoT;

typedef struct {
  int runFlag, recvFD, pid, listenPort, sendFD, tcpFlag, sendFlag;
  int msgID, alert, rule_id, severity, expPort, reqFlag, keyFlag;
  struct sockaddr_in expAddress;
  char str_begin_time[32], str_src_ip[32], str_dst_ip[32];
  char str_forward[32], str_retcode[32], str_src_port[32];
  char str_dst_port[32], str_req_header[32], str_req_body[32];
  char str_rsp_header[32], str_rsp_body[32], str_url[32];
  char str_method[32], str_message[32], str_domain[32];
  char hostname[128], progName[128], expDomain[128];
  char matched[65536], msg[65536];
} GlobalT;

#endif

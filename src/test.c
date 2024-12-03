#include "ms.h"
#include "util.h"

GlobalT global;

int main(int argc, char *argv[])
{
  char *p;
  cJSON *pRoot;
  HttpInfoT httpInfo;

  httpInfo.dport = 80;
  httpInfo.sport = 37762;
  global.alert = 0;
  strcpy(httpInfo.strClient, "127.0.0.1");
  strcpy(httpInfo.strServer, "127.0.0.1");
  strcpy(httpInfo.method, "GET");
  strcpy(httpInfo.strVersion, "1.1");
  strcpy(httpInfo.url, "/?param=%22%3E%3Cscript%3Ealert(1);%3C/script%3E");
  initMSC("/usr/local/openresty/nginx/conf/modsecurity/modsecurity.conf");
  processHttpTransaction(&httpInfo);
  printf("alert : %d\n", global.alert);
  printf("rule_id : %d\n", global.rule_id);
  printf("severity : %d\n", global.severity);
  printf("match : %s\n", global.matched);
  printf("msg : %s\n", global.msg);
  if(global.alert){
    pRoot = makeAlertJson(&httpInfo);
    p = cJSON_PrintUnformatted(pRoot);
    printf("json : %s\n", p);
    free(p);
    cJSON_Delete(pRoot);
  }
  return 0;
}

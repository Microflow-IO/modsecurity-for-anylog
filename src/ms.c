#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules_set.h>
#include "util.h"

extern GlobalT global;
ModSecurity *modsec;
RulesSet *rules;

extern GlobalT* getGlobal();
void getHeaderInfo(Transaction *transaction, HttpInfoT *pHttpInfo);

int initMSC(const char *filename)
{
  const char *error;

  error = 0;
  modsec = msc_init();
  rules = msc_create_rules_set();
  msc_rules_add_file(rules, filename, &error);
  if(error){
    printf("%s\n", error);
    return -1;
  }
  return 0;
}

int processHttpTransaction(HttpInfoT *pHttpInfo)
{
  Transaction *transaction;
  GlobalT *pGlobal;

  pGlobal = getGlobal();
  pGlobal->alert = 0;
  transaction = msc_new_transaction(modsec, rules, 0);
  msc_process_connection(transaction, pHttpInfo->strClient, pHttpInfo->sport, pHttpInfo->strServer, pHttpInfo->dport);
  msc_process_uri(transaction, pHttpInfo->url, pHttpInfo->method, pHttpInfo->strVersion);
  if(pGlobal->alert){
    msc_transaction_cleanup(transaction);
    strcpy(pHttpInfo->msg, pGlobal->msg);
    strcpy(pHttpInfo->matched, pGlobal->matched);
    return pGlobal->alert;
  }
  getHeaderInfo(transaction, pHttpInfo);
  msc_process_request_headers(transaction);
  if(pGlobal->alert){
    msc_transaction_cleanup(transaction);
    strcpy(pHttpInfo->msg, pGlobal->msg);
    strcpy(pHttpInfo->matched, pGlobal->matched);
    return pGlobal->alert;
  }
  msc_append_request_body(transaction, (unsigned char*)pHttpInfo->request_body, strlen(pHttpInfo->request_body));
  msc_process_request_body(transaction);
  msc_transaction_cleanup(transaction);
  strcpy(pHttpInfo->msg, pGlobal->msg);
  strcpy(pHttpInfo->matched, pGlobal->matched);
  return pGlobal->alert;
}

void getHeaderInfo(Transaction *transaction, HttpInfoT *pHttpInfo)
{
  msc_add_request_header(transaction, (unsigned char*)"Host", (unsigned char*)pHttpInfo->domain);
  msc_add_request_header(transaction, (unsigned char*)"Cookie", (unsigned char*)pHttpInfo->cookie);
  msc_add_request_header(transaction, (unsigned char*)"Referer", (unsigned char*)pHttpInfo->refer);
  msc_add_request_header(transaction, (unsigned char*)"Agent", (unsigned char*)pHttpInfo->agent);
}

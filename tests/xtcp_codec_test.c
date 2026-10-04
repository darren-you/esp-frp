// SPDX-License-Identifier: Apache-2.0
#include "xtcp_codec.h"
#include "xtcp_binding_internal.h"
#include "json_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xtcp_codec_vectors.h"
static uint8_t output[4096], storage[4096];
static char sid[65], nonce[65];
static void zero(const void *p, size_t n) { const uint8_t *s = p; for (size_t i=0;i<n;++i) assert(!s[i]); }
static void packet_decode(void)
{
    const uint8_t key[] = "public-key"; size_t n; efrp_xtcp_sid_message_t m;
    assert(efrp_xtcp_codec_sid_decode(go_order_datagram, sizeof go_order_datagram,key,sizeof key-1,&m)==EFRP_OK);
    assert(!strcmp(m.sid,sid)&&!strcmp(m.nonce,nonce)&&m.response&&!strcmp(m.transaction_id,"public-txn"));
    assert(efrp_xtcp_codec_sid_encode(&m,key,sizeof key-1,output,sizeof output,&n)==EFRP_OK);
    efrp_xtcp_sid_message_t result;
    assert(efrp_xtcp_codec_sid_decode(output,n,key,sizeof key-1,&result)==EFRP_OK);
    assert(!memcmp(&m,&result,sizeof m));
    for (size_t i=0;i<n;++i) {
        output[i]^=1;
        memset(&result,0xa5,sizeof result);
        assert(efrp_xtcp_codec_sid_decode(output,n,key,sizeof key-1,&result)!=EFRP_OK);
        zero(&result,sizeof result);output[i]^=1;
    }
    assert(efrp_xtcp_codec_sid_decode(output,n,(const uint8_t*)"wrong",5,&result)==EFRP_AUTHENTICATION_FAILED);
    assert(efrp_xtcp_codec_sid_decode(output,n-1,key,sizeof key-1,&result)==EFRP_PROTOCOL_ERROR);
    assert(efrp_xtcp_codec_sid_decode(output,n+1,key,sizeof key-1,&result)==EFRP_PROTOCOL_ERROR);
    assert(efrp_xtcp_codec_sid_encode(&m,key,sizeof key-1,output,n-1,&n)==EFRP_CAPACITY_EXCEEDED);
    assert(!n);
    m.nonce[0]='A';assert(efrp_xtcp_codec_sid_encode(&m,key,sizeof key-1,output,sizeof output,&n)==EFRP_INVALID_ARGUMENT);
    /* A correct MAC never excuses duplicate/unknown fields or wrong types. */
    const char *bad[]={"{\"sid\":\"x\",\"sid\":\"x\"}","{\"response\":1}","{\"unknown\":true}"};
    for(size_t i=0;i<sizeof bad/sizeof *bad;++i){
        size_t count=strlen(bad[i]);memcpy(output,"XHD1",4);output[4]=(uint8_t)(count>>8);output[5]=(uint8_t)count;memcpy(output+6,bad[i],count);
        efrp_crypto_span_t part={output,count+6};assert(efrp_xtcp_binding_hmac(key,sizeof key-1,&part,1,output+6+count)==EFRP_OK);
        assert(efrp_xtcp_codec_sid_decode(output,count+38,key,sizeof key-1,&result)==EFRP_PROTOCOL_ERROR);
    }
}
static size_t response(cJSON *root)
{
    char *json=cJSON_PrintUnformatted(root);assert(json);size_t n=strlen(json);assert(n+2<=sizeof output);
    output[0]=0;output[1]=22;memcpy(output+2,json,n);cJSON_free(json);return n+2;
}
static cJSON *valid_response(bool maximum)
{
    cJSON *root=cJSON_CreateObject();assert(root);
    assert(cJSON_AddStringToObject(root,"transaction_id","public-txn"));
    assert(cJSON_AddStringToObject(root,"sid",sid));assert(cJSON_AddStringToObject(root,"protocol","quic"));
    assert(cJSON_AddStringToObject(root,"binding_manifest",manifest_base64));assert(cJSON_AddStringToObject(root,"peer_certificate","AQIDBA=="));
    cJSON *cand=cJSON_AddArrayToObject(root,"candidate_addrs"),*assist=cJSON_AddArrayToObject(root,"assisted_addrs");
    for(unsigned i=0;i<(maximum?16u:2u);++i){char s[32];snprintf(s,sizeof s,"127.0.0.1:%u",10000+i);assert(cJSON_AddItemToArray(cand,cJSON_CreateString(s)));assert(cJSON_AddItemToArray(assist,cJSON_CreateString(s)));}
    cJSON *detect=cJSON_AddObjectToObject(root,"detect_behavior");
    assert(cJSON_AddStringToObject(detect,"role","receiver"));
    assert(cJSON_AddNumberToObject(detect,"mode",4));assert(cJSON_AddNumberToObject(detect,"ttl",7));
    assert(cJSON_AddNumberToObject(detect,"send_delay_ms",10000));assert(cJSON_AddNumberToObject(detect,"read_timeout",60000));
    assert(cJSON_AddNumberToObject(detect,"send_random_ports",1000));assert(cJSON_AddNumberToObject(detect,"listen_random_ports",256));
    cJSON *ranges=cJSON_AddArrayToObject(detect,"candidate_ports");
    for(unsigned i=0;i<(maximum?16u:2u);++i){cJSON *range=cJSON_CreateObject();assert(cJSON_AddNumberToObject(range,"from",100+i*10));assert(cJSON_AddNumberToObject(range,"to",109+i*10));assert(cJSON_AddItemToArray(ranges,range));}
    return root;
}
static void responses(void)
{
    size_t used,n;efrp_xtcp_signal_response_t r;
    output[0]=0;output[1]=22;memcpy(output+2,go_error_message,sizeof go_error_message-1);
    assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,sizeof go_error_message+1,storage,sizeof storage,&used,&r)==EFRP_WORK_REJECTED);
    assert(!strcmp(r.transaction_id,"public-txn")&&!strcmp(r.error,"public rejection")&&!r.sid);

    for(unsigned maximum=0;maximum<2;++maximum){
        cJSON *root=valid_response(maximum!=0);n=response(root);
        if(maximum){assert(!efrp_json_parse(output+2,n-2,EFRP_JSON_CONTROL_MAX_PUNCTUATION));cJSON *full=efrp_json_parse(output+2,n-2,EFRP_JSON_XTCP_MAX_PUNCTUATION);assert(full);cJSON_Delete(full);}
        assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage+1,sizeof storage-1,&used,&r)==EFRP_OK);
        assert(!strcmp(r.transaction_id,"public-txn")&&!strcmp(r.sid,sid)&&!r.error[0]);
        assert(r.candidate_address_count==(maximum?16u:2u)&&r.assisted_address_count==r.candidate_address_count);
        assert(r.detect.port_range_count==r.candidate_address_count&&r.detect.send_random_ports==1000&&r.detect.listen_random_ports==256);
        assert(r.detect.mode==4&&r.detect.ttl==7&&r.detect.read_timeout_ms==60000&&r.detect.send_delay_ms==10000);
        assert(r.candidate_addresses[1].port==10001&&r.peer_certificate_length==4&&r.peer_certificate[3]==4);
        efrp_xtcp_binding_manifest_t m;assert(efrp_xtcp_binding_decode(r.manifest,r.manifest_length,1700000005,&m)==EFRP_OK);
        /* All copied spans survive JSON/frame release; exact arena capacity works. */
        size_t exact=used;assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage+1,exact,&used,&r)==EFRP_OK);
        assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage+1,exact-1,&used,&r)==EFRP_CAPACITY_EXCEEDED);assert(!used);zero(&r,sizeof r);
        cJSON_ReplaceItemInObject(root,"peer_certificate",cJSON_CreateString("AQIDBB=="));n=response(root);
        assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);
        cJSON_Delete(root);
    }
    cJSON *root=valid_response(false);cJSON *detect=cJSON_GetObjectItemCaseSensitive(root,"detect_behavior");
    cJSON_AddNumberToObject(detect,"ttl",8);n=response(root);assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);cJSON_Delete(root);
    root=valid_response(false);cJSON_AddNumberToObject(root,"unknown",1);n=response(root);assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);cJSON_Delete(root);
    root=cJSON_CreateObject();cJSON_AddStringToObject(root,"transaction_id","public-txn");cJSON_AddStringToObject(root,"error","public rejection");cJSON_AddObjectToObject(root,"detect_behavior");n=response(root);
    assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_WORK_REJECTED);assert(!strcmp(r.error,"public rejection"));
    cJSON *empty_detect=cJSON_GetObjectItemCaseSensitive(root,"detect_behavior");cJSON_AddNumberToObject(empty_detect,"mode",0);n=response(root);
    assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);
    cJSON_ReplaceItemInObject(root,"detect_behavior",cJSON_CreateNumber(0));n=response(root);
    assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);cJSON_Delete(root);
    output[1]=17;assert(efrp_xtcp_codec_response(EFRP_MESSAGE,output,n,storage,sizeof storage,&used,&r)==EFRP_PROTOCOL_ERROR);
}
static void requests(void)
{
    efrp_xtcp_endpoint_t addresses[]={{{127,0,0,1},30000},{{127,0,0,1},30001}};
    uint8_t ctrl[32],ownnonce[32],spki[32],cert[1024];memset(ctrl,0x22,32);memset(ownnonce,0x44,32);memset(spki,0x66,32);memset(cert,0x31,sizeof cert);
    const uint8_t key[]="public-signal-secret";
    efrp_xtcp_signal_request_t r={.role=EFRP_XTCP_PROVIDER,.transaction_id="public-txn",.proxy_name="provider.private",.sid=sid,.secret=key,.secret_length=sizeof key-1,.control_id=ctrl,.nonce=ownnonce,.spki_sha256=spki,.certificate=cert,.certificate_length=sizeof cert,.timestamp_seconds=1700000000,.mapped_addresses=addresses,.mapped_address_count=2};
    size_t n,exact;
    for(unsigned i=0;i<2;++i){
        if(i){r.role=EFRP_XTCP_VISITOR;r.sid=NULL;}
        assert(efrp_xtcp_codec_request(&r,output,sizeof output,&n)==EFRP_OK);assert(n>1024&&output[8]==0&&output[9]==(i?20:21));
        cJSON *json=efrp_json_parse(output+10,n-10,EFRP_JSON_XTCP_MAX_PUNCTUATION);assert(json);
        assert(efrp_json_equals(json,"proxy_name","provider.private"));assert(!efrp_json_field(json,"sign_key")&&!efrp_json_field(json,"secret"));
        assert(i?efrp_json_equals(json,"protocol","quic")&&!efrp_json_field(json,"sid"):efrp_json_equals(json,"sid",sid)&&!efrp_json_field(json,"protocol"));
        if(!i)assert(efrp_json_equals(json,"signal_proof","qHi0NNy/8IeIZbXZkQkjVX0BJPW/b6R/ohKS6v5HRxU="));
        cJSON_Delete(json);exact=n;assert(efrp_xtcp_codec_request(&r,output,exact,&n)==EFRP_OK&&n==exact);
        assert(efrp_xtcp_codec_request(&r,output,exact-1,&n)==EFRP_CAPACITY_EXCEEDED&&!n);zero(output,exact-1);
    }
    r.sid=sid;assert(efrp_xtcp_codec_request(&r,output,sizeof output,&n)==EFRP_INVALID_ARGUMENT);
    r.sid=NULL;r.mapped_address_count=1;assert(efrp_xtcp_codec_request(&r,output,sizeof output,&n)==EFRP_INVALID_ARGUMENT);
    assert(efrp_xtcp_codec_report(sid,true,output,sizeof output,&n)==EFRP_OK&&output[9]==24);
    char work[128];snprintf(work,sizeof work,"{\"sid\":\"%s\"}",sid);output[0]=0;output[1]=23;memcpy(output+2,work,strlen(work));char decoded[65];
    assert(efrp_xtcp_codec_work_sid(EFRP_MESSAGE,output,strlen(work)+2,decoded)==EFRP_OK&&!strcmp(decoded,sid));output[1]=17;
    assert(efrp_xtcp_codec_work_sid(EFRP_MESSAGE,output,strlen(work)+2,decoded)==EFRP_PROTOCOL_ERROR);zero(decoded,sizeof decoded);
}
int main(void)
{
    memset(sid,'1',64);sid[64]=0;memset(nonce,'2',64);nonce[64]=0;
    packet_decode();responses();requests();puts("XTCP bounded signal/SID codec: PASS");return 0;
}

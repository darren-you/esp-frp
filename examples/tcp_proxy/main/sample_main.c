// SPDX-License-Identifier: Apache-2.0
#include "esp_frp.h"
#include "sample_echo.h"
#include "sample_resources.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "sample_inputs.h"

#if CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE
#error "The sample must not persist PHY calibration into an existing board's NVS"
#endif
static esp_netif_t *netif;
static atomic_bool wifi_started, wifi_ready, clock_synced;
static atomic_uint ip_generation, wifi_notice, sync_seconds;
static bool wifi_wanted=true;
static efrp_client_t *client;
static unsigned cycle;
static char previous_run_id[EFRP_RUN_ID_BYTES];

static bool trusted(void *context)
{
    (void)context;
    uint32_t now=(uint32_t)(esp_timer_get_time()/1000000);
    return atomic_load(&clock_synced) && now-atomic_load(&sync_seconds) < 7200u;
}
static void synced(struct timeval *tv)
{
    (void)tv;
    atomic_store(&sync_seconds, (unsigned)(esp_timer_get_time()/1000000));
    atomic_store(&clock_synced, true);
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) atomic_store(&wifi_started, true);
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_DISCONNECTED || id == WIFI_EVENT_STA_STOP))
        atomic_store(&wifi_ready, false);
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_STOP) atomic_store(&wifi_started, false);
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        atomic_fetch_add(&ip_generation, 1); atomic_store(&wifi_ready, true);
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) atomic_store(&wifi_ready, false);
    atomic_fetch_add(&wifi_notice, 1);
}
static bool inputs_valid(void)
{
    size_t ssid=sizeof sample_wifi_ssid-1, password=sizeof sample_wifi_password-1;
    const uint8_t loopback[4]={127,0,0,1};
    return ssid && ssid <= 32 && password >= 8 && password <= 64 &&
        sample_ntp_server[0] && sample_frp_config.ca_length && sample_frp_config.token_length &&
        sample_frp_config.local_port && !memcmp(loopback, sample_frp_config.local_ipv4, 4);
}
static esp_err_t start_wifi(void)
{
    esp_err_t error=esp_netif_init(); if (error != ESP_OK) return error;
    error=esp_event_loop_create_default(); if (error != ESP_OK) return error;
    netif=esp_netif_create_default_wifi_sta(); if (!netif) return ESP_ERR_NO_MEM;
    wifi_init_config_t init=WIFI_INIT_CONFIG_DEFAULT(); init.nvs_enable=false;
    error=esp_wifi_init(&init); if (error != ESP_OK) return error;
    if ((error=esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK ||
        (error=esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return error;
    wifi_config_t config={0};
    memcpy(config.sta.ssid, sample_wifi_ssid, sizeof sample_wifi_ssid-1);
    memcpy(config.sta.password, sample_wifi_password, sizeof sample_wifi_password-1);
    config.sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
    config.sta.pmf_cfg.capable=true;
    if ((error=esp_wifi_set_config(WIFI_IF_STA, &config)) != ESP_OK ||
        (error=esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL)) != ESP_OK ||
        (error=esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL)) != ESP_OK) return error;
    return esp_wifi_start();
}
static void clear_backup_dns(void *context)
{
    (void)context;
    /* esp_netif_set_dns_info rejects the zero address. Clearing is a raw lwIP
     * operation and must finish on its owner before SNTP/FRP can query. */
    for (u8_t i=1;i<DNS_MAX_SERVERS;++i) dns_setserver(i,NULL);
}
static esp_err_t set_dns(void)
{
    if (!sample_dns_ipv4[0]) return ESP_OK;
    esp_netif_dns_info_t dns={0}; dns.ip.type=ESP_IPADDR_TYPE_V4;
    if (inet_pton(AF_INET, sample_dns_ipv4, &dns.ip.u_addr.ip4.addr) != 1 || !dns.ip.u_addr.ip4.addr)
        return ESP_ERR_INVALID_ARG;
    esp_err_t error=esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    if (error != ESP_OK) return error;
    err_t cleared=tcpip_callback_wait(clear_backup_dns,NULL);
    return cleared == ERR_OK ? ESP_OK : (cleared == ERR_MEM ? ESP_ERR_NO_MEM : ESP_FAIL);
}
static efrp_result_t create_client(void)
{
    efrp_config_t config=sample_frp_config;
    config.time_is_trusted=trusted; config.previous_run_id=previous_run_id;
    efrp_result_t result=efrp_create(&config, &client);
    if (result == EFRP_OK) result=efrp_start(client);
    printf("EFRP_SAMPLE start_error=%d cycle=%u\n", result, cycle); return result;
}
static void report(const char *phase)
{
    efrp_status_t status={0};
    if (client) (void)efrp_get_status(client, &status);
    wifi_ap_record_t access_point={0};
    bool rssi_valid=esp_wifi_sta_get_ap_info(&access_point)==ESP_OK;
    printf("EFRP_SAMPLE_STATUS cycle=%u client=%u phase=%d error=%d attempts=%" PRIu64 " sessions=%" PRIu64
        " retries=%" PRIu64 " pongs=%" PRIu64 " active=%u waiting=%u completed=%" PRIu64 " failed=%" PRIu64
        " requests=%" PRIu64 " rejected=%" PRIu64 " pending=%u cleaning=%u"
        " work_error=%d sent=%" PRIu64 " received=%" PRIu64 " tls_error=%d verify=%" PRIu32
        " failure_phase=%d system_error=%d time_ms=%" PRIu64 " wifi=%u trusted=%u rssi_valid=%u rssi_dbm=%d remote=%s\n",
        cycle, client != NULL, status.phase, status.error, status.attempts, status.ready_sessions, status.retries,
        status.pongs, status.work.active, status.work.waiting, status.work.completed, status.work.failed,
        status.work.requests, status.work.rejected_requests, status.work.pending, status.work.cleaning,
        status.work.last_error, status.work.local_sent, status.work.local_received, status.tls_error, status.tls_verify_flags,
        status.failure_phase, status.system_error, (uint64_t)esp_timer_get_time()/1000u,
        atomic_load(&wifi_ready), trusted(NULL), rssi_valid, rssi_valid ? access_point.rssi : 0, status.remote_address);
    sample_echo_report(); sample_resources(phase, cycle);
}
static void command(const char *text)
{
    efrp_result_t result=EFRP_OK;
    uint64_t started=(uint64_t)esp_timer_get_time()/1000u;
    if (!strcmp(text,"stats")) { report("requested"); return; }
    if (!strcmp(text,"cycle") || !strcmp(text,"destroy") || !strcmp(text,"destroy_short")) {
        if (client) {
            efrp_status_t status; (void)efrp_get_status(client, &status);
            if (status.run_id[0]) memcpy(previous_run_id,status.run_id,sizeof previous_run_id);
        }
        result=efrp_destroy(&client,!strcmp(text,"destroy_short") ? 50 : 30000);
        if (result == EFRP_OK) {
            bool recreate=!strcmp(text,"cycle");
            if (recreate) ++cycle;
            /* app_main also owns the echo side. Let it close connections whose
             * matching work sockets were cancelled before measuring baseline. */
            for (unsigned i=0;i<10;++i) { sample_echo_step(); vTaskDelay(1); }
            report("destroyed");
            if (recreate) result=create_client();
        }
    } else if (!strcmp(text,"restart")) {
        result=client ? efrp_stop(client,30000) : EFRP_INVALID_STATE;
        if (result == EFRP_OK) result=efrp_start(client);
    } else if (!strcmp(text,"stop")) result=client ? efrp_stop(client,30000) : EFRP_OK;
    else if (!strcmp(text,"stop_poll")) result=client ? efrp_stop(client,0) : EFRP_OK;
    else if (!strcmp(text,"stop_short")) result=client ? efrp_stop(client,50) : EFRP_OK;
    else if (!strcmp(text,"start")) result=client ? efrp_start(client) : create_client();
    else if (!strcmp(text,"wifi_down")) { wifi_wanted=false; result=(efrp_result_t)esp_wifi_stop(); }
    else if (!strcmp(text,"wifi_up")) { wifi_wanted=true; result=(efrp_result_t)esp_wifi_start(); }
    else if (!strcmp(text,"echo_off")) sample_echo_stop();
    else if (!strcmp(text,"echo_on")) result=sample_echo_start(sample_frp_config.local_port) ? EFRP_OK : EFRP_NETWORK_ERROR;
    else { puts("EFRP_SAMPLE command_error=unknown"); return; }
    printf("EFRP_SAMPLE command=%s error=%d cycle=%u client=%u elapsed_ms=%" PRIu64 "\n",
        text,result,cycle,client!=NULL,(uint64_t)esp_timer_get_time()/1000u-started);
}
static void serial_input(void)
{
    static char line[64]; static size_t used; static bool overflow;
    uint8_t bytes[64]; int n=read(STDIN_FILENO,bytes,sizeof bytes);
    for (int i=0;i<n;++i) {
        if (bytes[i]=='\n') {
            if (overflow) puts("EFRP_SAMPLE command_error=too_long");
            else { line[used]=0; command(line); }
            used=0; overflow=false;
        } else if (bytes[i]!='\r') {
            if (used == sizeof line-1 || bytes[i]<32 || bytes[i]>126) overflow=true;
            else if (!overflow) line[used++]=(char)bytes[i];
        }
    }
}
void app_main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    puts("ESP_FRP_LAB_ONLY TCP_PROXY sdk=6.1 target=esp32c3");
    if (!inputs_valid()) { puts("EFRP_SAMPLE valid_private_inputs_required; no_network_started"); return; }
    sample_resources_init();
    usb_serial_jtag_vfs_use_nonblocking();
    int flags=fcntl(STDIN_FILENO,F_GETFL);
    if (flags<0 || fcntl(STDIN_FILENO,F_SETFL,flags & ~O_NONBLOCK)<0) { puts("EFRP_SAMPLE serial_init_failed"); return; }
    esp_err_t error=start_wifi();
    if (error != ESP_OK) { printf("EFRP_SAMPLE wifi_init_error=%d\n",error); return; }
    esp_sntp_config_t ntp=ESP_NETIF_SNTP_DEFAULT_CONFIG(sample_ntp_server); ntp.sync_cb=synced;
    ntp.start=false; /* Start only after DHCP and the selected DNS are ready. */
    error=esp_netif_sntp_init(&ntp);
    if (error != ESP_OK || !sample_echo_start(sample_frp_config.local_port)) {
        printf("EFRP_SAMPLE network_init_error=%d\n",error); return;
    }
    bool attempted=false;
    unsigned last_ip=0,last_wifi=0;
    uint64_t next_wifi=0,next_report=0;
    efrp_phase_t last_phase=EFRP_PHASE_STOPPED;
    uint64_t last_sessions=0;
    for (;;) {
        uint64_t now=(uint64_t)esp_timer_get_time()/1000u;
        if (atomic_load(&wifi_notice)!=last_wifi) {
            last_wifi=atomic_load(&wifi_notice);
            printf("EFRP_SAMPLE_WIFI started=%u ready=%u notice=%u\n",atomic_load(&wifi_started),atomic_load(&wifi_ready),last_wifi);
        }
        if (wifi_wanted && atomic_load(&wifi_started) && !atomic_load(&wifi_ready) && now>=next_wifi) {
            printf("EFRP_SAMPLE wifi_connect_error=%d\n",esp_wifi_connect()); next_wifi=now+5000;
        }
        unsigned generation=atomic_load(&ip_generation);
        if (atomic_load(&wifi_ready) && last_ip != generation) {
            error=set_dns(); printf("EFRP_SAMPLE dns_config_error=%d\n",error);
            if (error != ESP_OK) return;
            error=esp_netif_sntp_start(); printf("EFRP_SAMPLE sntp_start_error=%d\n",error);
            if (error != ESP_OK) return;
            last_ip=generation;
        }
        if (!attempted && atomic_load(&wifi_ready) && trusted(NULL)) {
            attempted=true; report("before_create"); (void)create_client();
        }
        if (client) {
            efrp_status_t status; (void)efrp_get_status(client,&status);
            if (status.phase!=last_phase || status.ready_sessions!=last_sessions) {
                last_phase=status.phase; last_sessions=status.ready_sessions;
                report(status.phase==EFRP_PHASE_READY ? "online" : "transition");
            }
        }
        serial_input(); sample_echo_step();
        if (now>=next_report) { report("periodic"); next_report=now+5000; }
        vTaskDelay(1);
    }
}

#include <kernel.h>
#include <lwip.h>

#define NTP_SERVER  "pool.ntp.org"
#define NTP_PORT    123

#define NTP_EPOCH_DELTA 2208988800ul    /* Number of seconds between 1900 and 1970 */

#define NTP_QUERY_INTERVAL  (10 * seconds(60))

#define NTP_MAX_SLEW_RATE   0.0005  /* 500 PPM */

struct ntp_ts {
    u32 seconds;
    u32 fraction;
};

struct ntp_packet {
    u8 mode:3;
    u8 vn:3;
    u8 li:2;
    u8 stratum;
    u8 poll;
    u8 precision;
    u32 root_delay;
    u32 root_dispersion;
    u32 reference_id;
    struct ntp_ts reference_ts;
    struct ntp_ts originate_ts;
    struct ntp_ts receive_ts;
    struct ntp_ts transmit_ts;
} __attribute((packed));

declare_closure_struct(0, 1, void, ntp_query_func,
    u64, overruns);

static struct {
    struct udp_pcb *pcb;
    closure_struct(ntp_query_func, query_func);
    timestamp last_raw;
    err_t (*dns_gethostbyname)(const char *hostname, ip_addr_t *addr,
            dns_found_callback found, void *callback_arg);
    struct pbuf *(*pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    u8 (*pbuf_free)(struct pbuf *p);
    err_t(*udp_sendto)(struct udp_pcb *pcb, struct pbuf *p,
            const ip_addr_t *dst_ip, u16_t dst_port);
    void (*runtime_memset)(u8 *a, u8 b, bytes len);
    timestamp (*now)(clock_id id);
    void (*clock_adjust)(timestamp now, double temp_cal, timestamp sync_complete, double cal);
} ntp;

static void timestamp_to_ntptime(timestamp t, struct ntp_ts *ntptime)
{
    ntptime->seconds = PP_HTONL(NTP_EPOCH_DELTA + sec_from_timestamp(t));
    ntptime->fraction = PP_HTONL((u32)t);
}

static timestamp ntptime_to_timestamp(struct ntp_ts *ntptime)
{
    return (seconds(PP_NTOHL(ntptime->seconds) - NTP_EPOCH_DELTA) + PP_NTOHL(ntptime->fraction));
}

static s64 ntptime_diff(struct ntp_ts *t1, struct ntp_ts *t2)
{
    return (seconds(PP_NTOHL(t1->seconds) - PP_NTOHL(t2->seconds)) +
            PP_NTOHL(t1->fraction) - PP_NTOHL(t2->fraction));
}

static void ntp_query(const ip_addr_t *server_addr)
{
    struct pbuf *p = ntp.pbuf_alloc(PBUF_TRANSPORT, sizeof(struct ntp_packet), PBUF_RAM);
    if (p == 0)
        return;
    struct ntp_packet *pkt = p->payload;
    ntp.runtime_memset(p->payload, 0, sizeof(*pkt));
    pkt->vn = 3;    /* NTP version number */
    pkt->mode = 3;  /* client mode */
    timestamp_to_ntptime(ntp.now(CLOCK_ID_REALTIME), &pkt->transmit_ts);
    ntp.udp_sendto(ntp.pcb, p, server_addr, NTP_PORT);
    ntp.pbuf_free(p);
}

static void ntp_input(void *z, struct udp_pcb *pcb, struct pbuf *p,
                      const ip_addr_t *addr, u16 port)
{
    struct ntp_packet *pkt = p->payload;
    if (p->len == sizeof(*pkt)) {
        timestamp wallclock_now = ntp.now(CLOCK_ID_REALTIME);
        timestamp origin = ntptime_to_timestamp(&pkt->originate_ts);
        /* round trip delay */
        timestamp rtd = wallclock_now - origin - ntptime_diff(&pkt->transmit_ts, &pkt->receive_ts);
        s64 offset = ntptime_to_timestamp(&pkt->transmit_ts) - wallclock_now + rtd / 2;
        double temp_cal, cal;
        timestamp raw = ntp.now(CLOCK_ID_MONOTONIC_RAW);

        /* Apply maximum slew rate until local time is synchronized with NTP time. */
        timestamp sync_complete;
        if (offset == 0) {
            temp_cal = 0;
            sync_complete = raw;
        } else {
            temp_cal = (offset > 0) ? NTP_MAX_SLEW_RATE : -NTP_MAX_SLEW_RATE;
            sync_complete = raw + offset / temp_cal;
        }

        /* If at least 2 samples have been received from NTP server, calculate calibration value to
         * to be applied after local time is synchronized with NTP time. */
        if ((ntp.last_raw != 0) && (raw != ntp.last_raw)) {
            cal = (double)offset / (raw - ntp.last_raw);
            if (cal > NTP_MAX_SLEW_RATE)
                cal = NTP_MAX_SLEW_RATE;
            else if (cal < -NTP_MAX_SLEW_RATE)
                cal = -NTP_MAX_SLEW_RATE;
        } else {
            cal = 0;
        }
        ntp.last_raw = raw;

        ntp.clock_adjust(wallclock_now + offset, temp_cal, sync_complete, cal);
    }
    ntp.pbuf_free(p);
}

static void ntp_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr)
        ntp_query(ipaddr);
}

define_closure_function(0, 1, void, ntp_query_func,
                        u64, overruns)
{
    ip_addr_t server_addr;
    err_t err = ntp.dns_gethostbyname(NTP_SERVER, &server_addr, ntp_dns_cb, 0);
    if (err == ERR_OK)
        ntp_query(&server_addr);
}

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    timer (*register_timer)(clock_id id, timestamp val, boolean absolute,
            timestamp interval, timer_handler n) = get_sym("kern_register_timer");
    struct udp_pcb *(*udp_new)(void) = get_sym("udp_new");
    void (*udp_recv)(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) = get_sym("udp_recv");
    if (!register_timer || !udp_new || !(ntp.dns_gethostbyname = get_sym("dns_gethostbyname")) ||
            !(ntp.pbuf_alloc = get_sym("pbuf_alloc")) || !(ntp.pbuf_free = get_sym("pbuf_free")) ||
            !(ntp.udp_sendto = get_sym("udp_sendto")) ||
            !(ntp.runtime_memset = get_sym("runtime_memset")) ||
            !(ntp.now = get_sym("now")) || !(ntp.clock_adjust = get_sym("clock_adjust")))
        return KLIB_INIT_FAILED;
    ntp.pcb = udp_new();
    if (!ntp.pcb)
        return KLIB_INIT_FAILED;
    udp_recv(ntp.pcb, ntp_input, 0);
    register_timer(CLOCK_ID_MONOTONIC_RAW, seconds(5), false, NTP_QUERY_INTERVAL,
                   init_closure(&ntp.query_func, ntp_query_func));
    return KLIB_INIT_OK;
}

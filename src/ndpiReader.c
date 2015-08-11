/*
 * ndpiReader.c
 * 
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2015 - QXIP BV
 * Copyright (C) 2015 - Diego Pino <dpino@igalia.com>
 *
 * Based on nDPI/ndpiReader.c
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>

#include "ndpi_api.h"
#include "ndpiReader.h"

#include <sys/socket.h>

/**
 * @brief Set main components necessary to the detection
 * @details TODO
 */
static void setupDetection();

/**
 * Client parameters
 */
static char *_protoFilePath   = NULL; /**< Protocol file path  */
static u_int8_t live_capture = 0, full_http_dissection = 0;
static u_int8_t undetected_flows_deleted = 0;
/**
 * User preferences
 */
static u_int8_t enable_protocol_guess = 1, nDPI_traceLevel = 0;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;

static struct timeval pcap_start, pcap_end;

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_for = 0;

#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024

#define NUM_ROOTS                 512

static u_int32_t num_flows;

struct thread_stats {
    u_int32_t guessed_flow_protocols;
    u_int64_t raw_packet_count;
    u_int64_t ip_packet_count;
    u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
    u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int32_t ndpi_flow_count;
    u_int64_t tcp_count, udp_count;
    u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
    u_int64_t packet_len[6];
    u_int16_t max_packet_len;
};

struct reader_thread {
    struct ndpi_detection_module_struct *ndpi_struct;
    void *ndpi_flows_root[NUM_ROOTS];
    u_int64_t last_time;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    int _pcap_datalink_type;

    /* TODO Add barrier */
    struct thread_stats stats;

    struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_info;

#define GTP_U_V1_PORT        2152
#define MAX_NDPI_FLOWS  200000000
/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
    u_int8_t ip[4];				//< Ip address
    struct ndpi_id_struct *ndpi_id;		//< nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;		//< ID tracking structure size

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// flow tracking
typedef struct ndpi_flow {  
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    u_int8_t detection_completed, protocol;
    u_int16_t vlan_id;
    struct ndpi_flow_struct *ndpi_flow;
    char lower_name[32], upper_name[32];

    u_int64_t last_seen;

    u_int64_t bytes;
    u_int32_t packets;

    // result only, not used for flow identification
    u_int32_t detected_protocol;

    char host_server_name[256];

    struct {
        char client_certificate[48], server_certificate[48];
    } ssl;

    void *src_id, *dst_id;
} ndpi_flow_t;


static u_int32_t size_flow_struct = 0;

/* ***************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct,
        ndpi_log_level_t log_level,
        const char *format, ...) {
    va_list va_ap;
    struct tm result;

    if (log_level <= nDPI_traceLevel) {
        char buf[8192], out_buf[8192];
        char theDate[32];
        const char *extra_msg = "";
        time_t theTime = time(NULL);

        va_start(va_ap, format);

        if (log_level == NDPI_LOG_ERROR)
            extra_msg = "ERROR: ";
        else if(log_level == NDPI_LOG_TRACE)
            extra_msg = "TRACE: ";
        else
            extra_msg = "DEBUG: ";

        memset(buf, 0, sizeof(buf));
        strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
        vsnprintf(buf, sizeof(buf)-1, format, va_ap);

        snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
        printf("%s", out_buf);
        fflush(stdout);
    }

    va_end(va_ap);
}

/* ***************************************************** */

static void *malloc_wrapper(unsigned long size) {
    current_ndpi_memory += size;

    if(current_ndpi_memory > max_ndpi_memory)
        max_ndpi_memory = current_ndpi_memory;

    return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
    free(freeable);
}

/* ***************************************************** */

static char* ipProto2Name(u_short proto_id) {
    static char proto[8];

    switch(proto_id) {
        case IPPROTO_TCP:
            return("TCP");
            break;
        case IPPROTO_UDP:
            return("UDP");
            break;
        case IPPROTO_ICMP:
            return("ICMP");
            break;
        case 112:
            return("VRRP");
            break;
        case IPPROTO_IGMP:
            return("IGMP");
            break;
    }

    snprintf(proto, sizeof(proto), "%u", proto_id);
    return(proto);
}

/* ***************************************************** */

static void printFlow(struct ndpi_flow *flow) {
    printf("\t%u", ++num_flows);

    printf("\t%s %s:%u <-> %s:%u ",
            ipProto2Name(flow->protocol),
            flow->lower_name, ntohs(flow->lower_port),
            flow->upper_name, ntohs(flow->upper_port));

    if(flow->vlan_id > 0) printf("[VLAN: %u]", flow->vlan_id);

    printf("[proto: %u/%s][%u pkts/%llu bytes]",
            flow->detected_protocol,
            ndpi_get_proto_name(ndpi_info.ndpi_struct, flow->detected_protocol),
            flow->packets, (long long unsigned int)flow->bytes);

    if(flow->host_server_name[0] != '\0') printf("[Host: %s]", flow->host_server_name);
    if(flow->ssl.client_certificate[0] != '\0') printf("[SSL client: %s]", flow->ssl.client_certificate);
    if(flow->ssl.server_certificate[0] != '\0') printf("[SSL server: %s]", flow->ssl.server_certificate);

    printf("\n");
}

/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
    if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
    if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
    if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
    struct ndpi_flow *flow = (struct ndpi_flow*)node;

    free_ndpi_flow(flow);
    ndpi_free(flow);
}

/* ***************************************************** */

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow**)node;

    if(flow->detected_protocol != 0 /* UNKNOWN */) return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
        printFlow(flow);
}

/* ***************************************************** */


static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow**)node;

    if(flow->detected_protocol == 0 /* UNKNOWN */) return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
        printFlow(flow);
}

/* ***************************************************** */

static unsigned int node_guess_undetected_protocol(struct ndpi_flow *flow) {
    flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_info.ndpi_struct,
            flow->protocol,
            ntohl(flow->lower_ip),
            ntohs(flow->lower_port),
            ntohl(flow->upper_ip),
            ntohs(flow->upper_port));
    // printf("Guess state: %u\n", flow->detected_protocol);
    if(flow->detected_protocol != 0)
        ndpi_info.stats.guessed_flow_protocols++;

    return flow->detected_protocol;
}

/* ***************************************************** */

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow **) node;

#if 0
    printf("<%d>Walk on node %s (%p)\n",
            depth,
            which == preorder?"preorder":
            which == postorder?"postorder":
            which == endorder?"endorder":
            which == leaf?"leaf": "unknown",
            flow);
#endif

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(enable_protocol_guess) {
            if(flow->detected_protocol == 0 /* UNKNOWN */) {
                node_guess_undetected_protocol(flow);
            }
        }

        ndpi_info.stats.protocol_counter[flow->detected_protocol]       += flow->packets;
        ndpi_info.stats.protocol_counter_bytes[flow->detected_protocol] += flow->bytes;
        ndpi_info.stats.protocol_flows[flow->detected_protocol]++;
    }
}

/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow **) node;

    if(ndpi_info.num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->last_seen + MAX_IDLE_TIME < ndpi_info.last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if (flow->detected_protocol == 0 /* UNKNOWN */ && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            free_ndpi_flow(flow);
            ndpi_info.stats.ndpi_flow_count--;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_info.idle_flows[ndpi_info.num_idle_flows++] = flow;
        }
    }
}

/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
    struct ndpi_flow *fa = (struct ndpi_flow*)a;
    struct ndpi_flow *fb = (struct ndpi_flow*)b;

    if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
    if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
    if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
    if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
    if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
    if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

    return(0);
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(
        const u_int8_t version,
        u_int16_t vlan_id,
        const struct ndpi_iphdr *iph,
        u_int16_t ip_offset,
        u_int16_t ipsize,
        u_int16_t l4_packet_len,
        struct ndpi_id_struct **src,
        struct ndpi_id_struct **dst,
        u_int8_t *proto,
        const struct ndpi_ip6_hdr *iph6) {
    u_int32_t idx, l4_offset;
    struct ndpi_tcphdr *tcph = NULL;
    struct ndpi_udphdr *udph = NULL;
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    struct ndpi_flow flow;
    void *ret;
    u_int8_t *l3;

    /*
Note: to keep things simple (ndpiReader is just a demo app)
we handle IPv6 a-la-IPv4.
*/
    if(version == 4) {
        if(ipsize < 20)
            return NULL;

        if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
                || (iph->frag_off & htons(0x1FFF)) != 0)
            return NULL;

        l4_offset = iph->ihl * 4;
        l3 = (u_int8_t*)iph;
    } else {
        l4_offset = sizeof(struct ndpi_ip6_hdr);
        l3 = (u_int8_t*)iph6;
    }

    if(l4_packet_len < 64)
        ndpi_info.stats.packet_len[0]++;
    else if(l4_packet_len >= 64 && l4_packet_len < 128)
        ndpi_info.stats.packet_len[1]++;
    else if(l4_packet_len >= 128 && l4_packet_len < 256)
        ndpi_info.stats.packet_len[2]++;
    else if(l4_packet_len >= 256 && l4_packet_len < 1024)
        ndpi_info.stats.packet_len[3]++;
    else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
        ndpi_info.stats.packet_len[4]++;
    else if(l4_packet_len >= 1500)
        ndpi_info.stats.packet_len[5]++;

    if(l4_packet_len > ndpi_info.stats.max_packet_len)
        ndpi_info.stats.max_packet_len = l4_packet_len;

    if(iph->saddr < iph->daddr) {
        lower_ip = iph->saddr;
        upper_ip = iph->daddr;
    } else {
        lower_ip = iph->daddr;
        upper_ip = iph->saddr;
    }

    *proto = iph->protocol;

    if(iph->protocol == 6 && l4_packet_len >= 20) {
        ndpi_info.stats.tcp_count++;

        // tcp
        tcph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset);
        if(iph->saddr < iph->daddr) {
            lower_port = tcph->source;
            upper_port = tcph->dest;
        } else {
            lower_port = tcph->dest;
            upper_port = tcph->source;

            if(iph->saddr == iph->daddr) {
                if(lower_port > upper_port) {
                    u_int16_t p = lower_port;

                    lower_port = upper_port;
                    upper_port = p;
                }
            }
        }
    } else if(iph->protocol == 17 && l4_packet_len >= 8) {
        // udp
        ndpi_info.stats.udp_count++;

        udph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset);
        if(iph->saddr < iph->daddr) {
            lower_port = udph->source;
            upper_port = udph->dest;
        } else {
            lower_port = udph->dest;
            upper_port = udph->source;
        }
    } else {
        // non tcp/udp protocols
        lower_port = 0;
        upper_port = 0;
    }

    flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
    flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
    flow.lower_port = lower_port, flow.upper_port = upper_port;

    if(0)
        printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
                iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

    idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
    ret = ndpi_tfind(&flow, &ndpi_info.ndpi_flows_root[idx], node_cmp);

    if(ret == NULL) {
        if(ndpi_info.stats.ndpi_flow_count == MAX_NDPI_FLOWS) {
            printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
            exit(-1);
        } else {
            struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

            if(newflow == NULL) {
                printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
                return(NULL);
            }

            memset(newflow, 0, sizeof(struct ndpi_flow));
            newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
            newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
            newflow->lower_port = lower_port, newflow->upper_port = upper_port;

            if(version == 4) {
                inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
                inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
            } else {
                inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
                inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
            }

            if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
                printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
                return(NULL);
            } else
                memset(newflow->ndpi_flow, 0, size_flow_struct);

            if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
                printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
                return(NULL);
            } else
                memset(newflow->src_id, 0, size_id_struct);

            if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
                printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
                return(NULL);
            } else
                memset(newflow->dst_id, 0, size_id_struct);

            ndpi_tsearch(newflow, &ndpi_info.ndpi_flows_root[idx], node_cmp); /* Add */
            ndpi_info.stats.ndpi_flow_count++;

            *src = newflow->src_id, *dst = newflow->dst_id;

            return(newflow);
        }
    } else {
        struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

        if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
                && flow->lower_port == lower_port && flow->upper_port == upper_port)
            *src = flow->src_id, *dst = flow->dst_id;
        else
            *src = flow->dst_id, *dst = flow->src_id;

        return flow;
    }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow6(
        u_int16_t vlan_id,
        const struct ndpi_ip6_hdr *iph6,
        u_int16_t ip_offset,
        struct ndpi_id_struct **src,
        struct ndpi_id_struct **dst,
        u_int8_t *proto) {
    struct ndpi_iphdr iph;

    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
    iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
    iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if(iph.protocol == 0x3C /* IPv6 destination option */) {
        u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ip6_hdr);

        iph.protocol = options[0];
    }

    return(get_ndpi_flow(6, vlan_id, &iph, ip_offset,
                sizeof(struct ndpi_ip6_hdr),
                ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
                src, dst, proto, iph6));
}

/* ***************************************************** */

static void setupDetection() {
    NDPI_PROTOCOL_BITMASK all;

    memset(&ndpi_info, 0, sizeof(ndpi_info));

    // init global detection structure
    ndpi_info.ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, 
            malloc_wrapper, free_wrapper, debug_printf);
    if(ndpi_info.ndpi_struct == NULL) {
        printf("ERROR: global structure initialization failed\n");
        exit(-1);
    }

    if(full_http_dissection)
        ndpi_info.ndpi_struct->http_dissect_response = 1;

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info.ndpi_struct, &all);

    // allocate memory for id and flow tracking
    size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    // clear memory for results
    memset(ndpi_info.stats.protocol_counter, 0, sizeof(ndpi_info.stats.protocol_counter));
    memset(ndpi_info.stats.protocol_counter_bytes, 0, sizeof(ndpi_info.stats.protocol_counter_bytes));
    memset(ndpi_info.stats.protocol_flows, 0, sizeof(ndpi_info.stats.protocol_flows));

    if(_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_info.ndpi_struct, _protoFilePath);
}

/* ***************************************************** */

static void terminateDetection() {
    int i;

    for (i=0; i<NUM_ROOTS; i++) {
        ndpi_tdestroy(ndpi_info.ndpi_flows_root[i], ndpi_flow_freer);
        ndpi_info.ndpi_flows_root[i] = NULL;
    }

    ndpi_exit_detection_module(ndpi_info.ndpi_struct, free_wrapper);
}

/* ***************************************************** */

callback protocolHandler;

void addProtocolHandler(callback handler) {
    protocolHandler = handler;
}

void onProtocol(uint16_t id, const uint8_t *packet) {
    if (protocolHandler) {
        protocolHandler(id, packet);
    }
}

/* ***************************************************** */

// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(
        const uint8_t *packet,
        const u_int64_t time,
        u_int16_t vlan_id,
        const struct ndpi_iphdr *iph,
        struct ndpi_ip6_hdr *iph6,
        u_int16_t ip_offset,
        u_int16_t ipsize, 
        u_int16_t rawsize) {

    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow *flow;
    struct ndpi_flow_struct *ndpi_flow = NULL;
    u_int32_t protocol = 0;
    u_int8_t proto;

    if (iph)
        flow = get_ndpi_flow(4, vlan_id, iph, ip_offset, ipsize,
                ntohs(iph->tot_len) - (iph->ihl * 4),
                &src, &dst, &proto, NULL);
    else
        flow = get_ndpi_flow6(vlan_id, iph6, ip_offset, &src, &dst, &proto);

    if (flow != NULL) {
        ndpi_info.stats.ip_packet_count++;
        ndpi_info.stats.total_wire_bytes += rawsize + 24 /* CRC etc */, ndpi_info.stats.total_ip_bytes += rawsize;
        ndpi_flow = flow->ndpi_flow;
        flow->packets++, flow->bytes += rawsize;
        flow->last_seen = time;
    } else {
        return(0);
    }

    if (flow->detection_completed) {
        onProtocol(flow->detected_protocol, packet);
        return(0);
    }

    protocol = (const u_int32_t) ndpi_detection_process_packet(ndpi_info.ndpi_struct, ndpi_flow,
            iph ? (uint8_t *)iph : (uint8_t *)iph6,
            ipsize, time, src, dst);

    flow->detected_protocol = protocol;

    if ((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
            || ((proto == IPPROTO_UDP) && (flow->packets > 8))
            || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
        flow->detection_completed = 1;

        snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

        if ((proto == IPPROTO_TCP) && (flow->detected_protocol != NDPI_PROTOCOL_DNS)) {
            snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
        }

        if (((flow->detected_protocol == NDPI_PROTOCOL_HTTP) 
                || (flow->detected_protocol == NDPI_SERVICE_FACEBOOK))
                && full_http_dissection) {
            char *method;

            printf("[URL] %s\n", ndpi_get_http_url(ndpi_info.ndpi_struct, ndpi_flow));
            printf("[Content-Type] %s\n", ndpi_get_http_content_type(ndpi_info.ndpi_struct, ndpi_flow));     

            switch(ndpi_get_http_method(ndpi_info.ndpi_struct, ndpi_flow)) {
                case HTTP_METHOD_OPTIONS: method = "HTTP_METHOD_OPTIONS"; break;
                case HTTP_METHOD_GET: method = "HTTP_METHOD_GET"; break;
                case HTTP_METHOD_HEAD: method = "HTTP_METHOD_HEAD"; break;
                case HTTP_METHOD_POST: method = "HTTP_METHOD_POST"; break;
                case HTTP_METHOD_PUT: method = "HTTP_METHOD_PUT"; break;
                case HTTP_METHOD_DELETE: method = "HTTP_METHOD_DELETE"; break;
                case HTTP_METHOD_TRACE: method = "HTTP_METHOD_TRACE"; break;
                case HTTP_METHOD_CONNECT: method = "HTTP_METHOD_CONNECT"; break;
                default: method = "HTTP_METHOD_UNKNOWN"; break;
            }

            printf("[Method] %s\n", method);
        }

        free_ndpi_flow(flow);

        if (enable_protocol_guess) {
            if (flow->detected_protocol == 0) {
                protocol = node_guess_undetected_protocol(flow);
            }
        }
        onProtocol(flow->detected_protocol, packet);
    }

    if (live_capture) {
        if (ndpi_info.last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_info.last_time) {
            /* scan for idle flows */
            ndpi_twalk(ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_idle_scan_walker, 0);

            /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_info.num_idle_flows > 0)
                ndpi_tdelete(ndpi_info.idle_flows[--ndpi_info.num_idle_flows],
                        &ndpi_info.ndpi_flows_root[ndpi_info.idle_scan_idx], node_cmp);

            if (++ndpi_info.idle_scan_idx == NUM_ROOTS) ndpi_info.idle_scan_idx = 0;
            ndpi_info.last_idle_scan_time = ndpi_info.last_time;
        }
    }
    return 0;
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
    char unit;

    if(bits)
        unit = 'b';
    else
        unit = 'B';

    if(numBits < 1024) {
        snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
    } else if(numBits < 1048576) {
        snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
    } else {
        float tmpMBits = ((float)numBits)/1048576;

        if(tmpMBits < 1024) {
            snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        } else {
            tmpMBits /= 1024;

            if(tmpMBits < 1024) {
                snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            } else {
                snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
            }
        }
    }

    return(buf);
}

/* ***************************************************** */

char* formatPackets(float numPkts, char *buf) {
    if(numPkts < 1000) {
        snprintf(buf, 32, "%.2f", numPkts);
    } else if(numPkts < 1000000) {
        snprintf(buf, 32, "%.2f K", numPkts/1000);
    } else {
        numPkts /= 1000000;
        snprintf(buf, 32, "%.2f M", numPkts);
    }

    return(buf);
}

/* ***************************************************** */

char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
    char unit = 'B';

    if(howMuch < 1024) {
        snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
    } else if(howMuch < 1048576) {
        snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
    } else {
        float tmpGB = ((float)howMuch)/1048576;

        if(tmpGB < 1024) {
            snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
        } else {
            tmpGB /= 1024;

            snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
        }
    }

    return(buf);
}

static void printNDPIMemoryStats() {
    char buf[32];

    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(sizeof(struct ndpi_detection_module_struct), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(size_flow_struct, buf, sizeof(buf)));
    printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
}

static void printTrafficStats(u_int64_t tot_usec, struct thread_stats cumulative_stats) {
    u_int avg_pkt_size = 0;

    printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
            (long long unsigned int)cumulative_stats.total_wire_bytes);
    printf("\tDiscarded bytes:       %-13llu\n",
            (long long unsigned int)cumulative_stats.total_discarded_bytes);
    printf("\tIP packets:            %-13llu of %llu packets total\n",
            (long long unsigned int)cumulative_stats.ip_packet_count,
            (long long unsigned int)cumulative_stats.raw_packet_count);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
        avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
            (long long unsigned int)cumulative_stats.total_ip_bytes,avg_pkt_size);
    printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);

    printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
    printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
    printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
    printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
    printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
    printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
    printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
    printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
    printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
    printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
    printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
    printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
    printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

    if (tot_usec > 0) {
        char buf[32], buf1[32];
        float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)tot_usec;
        float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)tot_usec;
        float traffic_duration;
        if (live_capture) traffic_duration = tot_usec;
        else traffic_duration = (pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - (pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
        printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
        t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
        b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
        printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
        printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
    }

    if (enable_protocol_guess)
        printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);
}

static u_int64_t printProtocolsInfo(long long unsigned int *breed_stats, struct thread_stats cumulative_stats) {
    u_int64_t total_flow_bytes = 0;
    u_int32_t i;

    for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_info.ndpi_struct); i++) {
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_info.ndpi_struct, i);

        if (cumulative_stats.protocol_counter[i] > 0) {
            breed_stats[breed] += (long long unsigned int) cumulative_stats.protocol_counter_bytes[i];

            printf("\t%-20s packets: %-13llu bytes: %-13llu "
                    "flows: %-13u\n",
                    ndpi_get_proto_name(ndpi_info.ndpi_struct, i),
                    (long long unsigned int)cumulative_stats.protocol_counter[i],
                    (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
                    cumulative_stats.protocol_flows[i]);
        }
        total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
    }
    return total_flow_bytes;
}

static void printProtocolStats(long long unsigned int *breed_stats) {
    u_int32_t i;

    for (i = 0; i < NUM_BREEDS; i++) {
        if(breed_stats[i] > 0) {
            printf("\t%-20s %13llu bytes\n",
                    ndpi_get_proto_breed_name(ndpi_info.ndpi_struct, i),
                    breed_stats[i]);
        }
    }
}

static void aggregateStats(struct thread_stats *cumulative_stats) {
    u_int32_t i;

    if (ndpi_info.stats.total_wire_bytes != 0) {
        for (i=0; i<NUM_ROOTS; i++)
            ndpi_twalk(ndpi_info.ndpi_flows_root[i], node_proto_guess_walker, 0);

        /* Stats aggregation */
        cumulative_stats->guessed_flow_protocols += ndpi_info.stats.guessed_flow_protocols;
        cumulative_stats->raw_packet_count += ndpi_info.stats.raw_packet_count;
        cumulative_stats->ip_packet_count += ndpi_info.stats.ip_packet_count;
        cumulative_stats->total_wire_bytes += ndpi_info.stats.total_wire_bytes;
        cumulative_stats->total_ip_bytes += ndpi_info.stats.total_ip_bytes;
        cumulative_stats->total_discarded_bytes += ndpi_info.stats.total_discarded_bytes;

        for (i = 0; i < ndpi_get_num_supported_protocols(ndpi_info.ndpi_struct); i++) {
            cumulative_stats->protocol_counter[i] += ndpi_info.stats.protocol_counter[i];
            cumulative_stats->protocol_counter_bytes[i] += ndpi_info.stats.protocol_counter_bytes[i];
            cumulative_stats->protocol_flows[i] += ndpi_info.stats.protocol_flows[i];
        }

        cumulative_stats->ndpi_flow_count += ndpi_info.stats.ndpi_flow_count;
        cumulative_stats->tcp_count   += ndpi_info.stats.tcp_count;
        cumulative_stats->udp_count   += ndpi_info.stats.udp_count;
        cumulative_stats->mpls_count  += ndpi_info.stats.mpls_count;
        cumulative_stats->pppoe_count += ndpi_info.stats.pppoe_count;
        cumulative_stats->vlan_count  += ndpi_info.stats.vlan_count;
        cumulative_stats->fragmented_count += ndpi_info.stats.fragmented_count;
        for(i = 0; i < 6; i++)
            cumulative_stats->packet_len[i] += ndpi_info.stats.packet_len[i];
        cumulative_stats->max_packet_len += ndpi_info.stats.max_packet_len;
    }
}

/* ***************************************************** */

static void printResults(u_int64_t tot_usec) {
    u_int32_t i;
    struct thread_stats cumulative_stats;
    long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

    memset(&cumulative_stats, 0, sizeof(cumulative_stats));

    aggregateStats(&cumulative_stats);

    printf("\nnDPI Memory statistics:\n");
    printNDPIMemoryStats();

    // Traffic statistics
    printf("\nTraffic statistics:\n");
    printTrafficStats(tot_usec, cumulative_stats);

    // Detected protocols
    printf("\n\nDetected protocols:\n");
    printProtocolsInfo(breed_stats, cumulative_stats);

    // Protocol statistics
    printf("\n\nProtocol statistics:\n");
    printProtocolStats(breed_stats);
}

/* ***************************************************** */

int calculateTypeAndIpOffset(u_int16_t *type, u_int16_t *ip_offset, const u_int8_t *packet) {
    const struct ndpi_ethhdr *ethernet;

    if (ndpi_info._pcap_datalink_type == DLT_NULL) {
        if (ntohl(*((u_int32_t*) packet)) == 2)
            *type = ETH_P_IP;
        else
            *type = 0x86DD; /* IPv6 */
        *ip_offset = 4;
    } else if (ndpi_info._pcap_datalink_type == DLT_EN10MB) {
        ethernet = (struct ndpi_ethhdr *) packet;
        *ip_offset = sizeof(struct ndpi_ethhdr);
        *type = ntohs(ethernet->h_proto);
    } else if (ndpi_info._pcap_datalink_type == 113 /* Linux Cooked Capture */) {
        *type = (packet[14] << 8) + packet[15];
        *ip_offset = 16;
    } else 
        return 0;
    return 1;
}

static void pcap_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ndpi_iphdr *iph;
    struct ndpi_ip6_hdr *iph6;
    u_int64_t time;
    u_int16_t type, ip_offset, ip_len;
    u_int16_t frag_off = 0, vlan_id = 0;
    u_int8_t proto = 0, vlan_packet = 0;

    ndpi_info.stats.raw_packet_count++;

    if (!live_capture) {
        if (!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
        pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;
    }

    time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
        header->ts.tv_usec / (1000000 / detection_tick_resolution);

    if(ndpi_info.last_time > time) { /* safety check */
        // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_info.last_time - time);
        time = ndpi_info.last_time;
    }
    ndpi_info.last_time = time;

    if (!calculateTypeAndIpOffset(&type, &ip_offset, packet))
        return;

    while(1) {
        if(type == 0x8100 /* VLAN */) {
            vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
            type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
            ip_offset += 4;
            vlan_packet = 1;
        } else if(type == 0x8847 /* MPLS */) {
            u_int32_t label = ntohl(*((u_int32_t*)&packet[ip_offset]));

            ndpi_info.stats.mpls_count++;
            type = 0x800, ip_offset += 4;

            while((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(*((u_int32_t*)&packet[ip_offset]));
            }
        } else if(type == 0x8864 /* PPPoE */) {
            ndpi_info.stats.pppoe_count++;
            type = 0x0800;
            ip_offset += 8;
        } else
            break;
    }

    ndpi_info.stats.vlan_count += vlan_packet;

    iph = (struct ndpi_iphdr *) &packet[ip_offset];

    // just work on Ethernet packets that contain IP
    if (type == ETH_P_IP && header->caplen >= ip_offset) {
        frag_off = ntohs(iph->frag_off);

        proto = iph->protocol;
        if(header->caplen < header->len) {
            static u_int8_t cap_warning_used = 0;

            if(cap_warning_used == 0) {
                printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
                cap_warning_used = 1;
            }
        }
    }

    if (iph->version == 4) {
        ip_len = ((u_short)iph->ihl * 4);
        iph6 = NULL;

        if((frag_off & 0x3FFF) != 0) {
            static u_int8_t ipv4_frags_warning_used = 0;

            ndpi_info.stats.fragmented_count++;
            if(ipv4_frags_warning_used == 0) {
                printf("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
                ipv4_frags_warning_used = 1;
            }

            ndpi_info.stats.total_discarded_bytes +=  header->len;
            return;
        }
    } else if(iph->version == 6) {
        iph6 = (struct ndpi_ip6_hdr *)&packet[ip_offset];
        proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        ip_len = sizeof(struct ndpi_ip6_hdr);

        if(proto == 0x3C /* IPv6 destination option */) {
            u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];

            proto = options[0];
            ip_len += 8 * (options[1] + 1);
        }

        iph = NULL;
    } else {
        static u_int8_t ipv4_warning_used = 0;

v4_warning:
        if(ipv4_warning_used == 0) {
            printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
            ipv4_warning_used = 1;
        }

        ndpi_info.stats.total_discarded_bytes +=  header->len;
        return;
    }

    if (decode_tunnels && (proto == IPPROTO_UDP)) {
        struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
        u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

        if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
            /* Check if it's GTPv1 */
            u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
            u_int8_t flags = packet[offset];
            u_int8_t message_type = packet[offset+1];

            if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
                ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

                if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
                if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
                if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

                iph = (struct ndpi_iphdr *) &packet[ip_offset];

                if(iph->version != 4) {
                    // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)ndpi_info.stats.raw_packet_count);
                    goto v4_warning;
                }
            }
        }
    }

    // process the packet
    packet_processing(packet, time, vlan_id, iph, iph6,
            ip_offset, header->len - ip_offset, header->len);
}

/* ******************************************************************** */

struct timeval begin, end;
u_int64_t tot_usec;

void init() {
    memset(&pcap_start, 0, sizeof(pcap_start));
    memset(&pcap_end, 0, sizeof(pcap_end));
    setupDetection();
    gettimeofday(&begin, NULL);
}

void setDatalinkType(pcap_t *handle) {
    ndpi_info._pcap_datalink_type = pcap_datalink(handle);
}

void processPacket(const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_packet_callback(NULL, header, packet);
}

void finish() {
    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    printResults(tot_usec);
    terminateDetection();
}

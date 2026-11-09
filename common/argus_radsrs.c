/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2026 QoSient, LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 */

/*
 * Shared radsrs JSON serializer for native Argus records.
 *
 * The raw record is authoritative.  Argus canonicalizes records before
 * calling RaProcessRecord(), so radsrs serializes input->ArgusOriginal while
 * that input buffer is still associated with the current callback.  The
 * canonical section is a readable projection of the ArgusRecordStruct slots.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <arpa/inet.h>
#include <float.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_threads.h>
#include <argus_radsrs.h>

#define RADSRS_SCHEMA "argus.radsrs/1"

struct RadsrsWriter {
   FILE *stream;
   char *data;
   size_t length;
   size_t capacity;
   int failed;
};

/* The renderer routes legacy output calls through one active writer context. */
static struct RadsrsWriter *RadsrsActiveWriter;

#if defined(ARGUS_THREADS)
static pthread_mutex_t RadsrsWriterLock = PTHREAD_MUTEX_INITIALIZER;
#endif

static int
RadsrsWriterBegin(struct RadsrsWriter *writer)
{
#if defined(ARGUS_THREADS)
   if (pthread_mutex_trylock(&RadsrsWriterLock) != 0) {
      errno = EBUSY;
      return -1;
   }
#endif
   if (RadsrsActiveWriter != NULL) {
#if defined(ARGUS_THREADS)
      (void)pthread_mutex_unlock(&RadsrsWriterLock);
#endif
      errno = EBUSY;
      return -1;
   }
   RadsrsActiveWriter = writer;
   return 0;
}

static void
RadsrsWriterEnd(void)
{
   RadsrsActiveWriter = NULL;
#if defined(ARGUS_THREADS)
   (void)pthread_mutex_unlock(&RadsrsWriterLock);
#endif
}

static int
RadsrsWriterReserve(struct RadsrsWriter *writer, size_t additional)
{
   size_t required;
   size_t capacity;
   char *data;

   if ((writer == NULL) || writer->failed)
      return -1;
   if (writer->stream != NULL)
      return 0;
   if (additional > ((size_t)-1 - writer->length - 1)) {
      writer->failed = 1;
      errno = EOVERFLOW;
      return -1;
   }

   required = writer->length + additional + 1;
   if (required <= writer->capacity)
      return 0;

   capacity = writer->capacity ? writer->capacity : 1024;
   while (capacity < required) {
      if (capacity > ((size_t)-1 / 2)) {
         capacity = required;
         break;
      }
      capacity *= 2;
   }

   data = realloc(writer->data, capacity);
   if (data == NULL) {
      writer->failed = 1;
      errno = ENOMEM;
      return -1;
   }

   writer->data = data;
   writer->capacity = capacity;
   return 0;
}

static void
RadsrsWriterAppend(const char *data, size_t length)
{
   struct RadsrsWriter *writer = RadsrsActiveWriter;

   if ((writer == NULL) || writer->failed)
      return;

   if (writer->stream != NULL) {
      if (fwrite(data, 1, length, writer->stream) != length)
         writer->failed = 1;
      return;
   }

   if (RadsrsWriterReserve(writer, length) < 0)
      return;
   memcpy(writer->data + writer->length, data, length);
   writer->length += length;
   writer->data[writer->length] = '\0';
}

static void
RadsrsPuts(const char *text)
{
   RadsrsWriterAppend(text, strlen(text));
}

static void
RadsrsPutc(int character)
{
   char text = (char)character;

   RadsrsWriterAppend(&text, 1);
}

static void
RadsrsPrintf(const char *format, ...)
{
   va_list args;
   va_list copy;
   int written;
   size_t length;
   char stack[256];
   char *text = stack;

   va_start(args, format);
   va_copy(copy, args);
   written = vsnprintf(NULL, 0, format, copy);
   va_end(copy);
   if (written < 0) {
      if (RadsrsActiveWriter != NULL)
         RadsrsActiveWriter->failed = 1;
      va_end(args);
      return;
   }

   length = (size_t)written;
   if (length >= sizeof(stack)) {
      text = malloc(length + 1);
      if (text == NULL) {
         if (RadsrsActiveWriter != NULL)
            RadsrsActiveWriter->failed = 1;
         va_end(args);
         return;
      }
   }

   (void)vsnprintf(text, length + 1, format, args);
   va_end(args);
   RadsrsWriterAppend(text, length);
   if (text != stack)
      free(text);
}

/* Keep the established renderer text unchanged while routing to a sink. */
#define fputs(text, stream) RadsrsPuts(text)
#define fputc(character, stream) RadsrsPutc(character)
#define fprintf(stream, ...) RadsrsPrintf(__VA_ARGS__)

static void
RadsrsIndent(int level)
{
   int i;

   for (i = 0; i < level; i++)
      fputs("  ", stdout);
}

static void
RadsrsJsonStringN(const unsigned char *value, size_t length)
{
   size_t i;

   fputc('"', stdout);
   for (i = 0; i < length; i++) {
      unsigned char c = value[i];

      switch (c) {
         case '"':
            fputs("\\\"", stdout);
            break;
         case '\\':
            fputs("\\\\", stdout);
            break;
         case '\b':
            fputs("\\b", stdout);
            break;
         case '\f':
            fputs("\\f", stdout);
            break;
         case '\n':
            fputs("\\n", stdout);
            break;
         case '\r':
            fputs("\\r", stdout);
            break;
         case '\t':
            fputs("\\t", stdout);
            break;
         default:
            /* JSON text must be Unicode.  Preserve arbitrary bytes in the
             * accompanying Base64 field and escape non-ASCII display bytes. */
            if ((c < 0x20) || (c >= 0x7f))
               fprintf(stdout, "\\u%04x", c);
            else
               fputc(c, stdout);
            break;
      }
   }
   fputc('"', stdout);
}

static void
RadsrsJsonString(const char *value)
{
   if (value == NULL) {
      fputs("null", stdout);
      return;
   }

   RadsrsJsonStringN((const unsigned char *)value, strlen(value));
}

static void
RadsrsJsonBase64(const unsigned char *data, size_t length)
{
   static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   size_t i;

   fputc('"', stdout);
   for (i = 0; (i + 2) < length; i += 3) {
      unsigned int value = ((unsigned int)data[i] << 16) |
                           ((unsigned int)data[i + 1] << 8) |
                           (unsigned int)data[i + 2];

      fputc(table[(value >> 18) & 0x3f], stdout);
      fputc(table[(value >> 12) & 0x3f], stdout);
      fputc(table[(value >> 6) & 0x3f], stdout);
      fputc(table[value & 0x3f], stdout);
   }

   if (i < length) {
      unsigned int value = (unsigned int)data[i] << 16;

      if ((i + 1) < length)
         value |= (unsigned int)data[i + 1] << 8;

      fputc(table[(value >> 18) & 0x3f], stdout);
      fputc(table[(value >> 12) & 0x3f], stdout);
      if ((i + 1) < length) {
         fputc(table[(value >> 6) & 0x3f], stdout);
         fputc('=', stdout);
      } else {
         fputc('=', stdout);
         fputc('=', stdout);
      }
   }
   fputc('"', stdout);
}

static void
RadsrsJsonUInt64(unsigned long long value)
{
   char buf[32];

   snprintf(buf, sizeof(buf), "%llu", value);
   RadsrsJsonString(buf);
}

static void
RadsrsJsonInt64(long long value)
{
   char buf[32];

   snprintf(buf, sizeof(buf), "%lld", value);
   RadsrsJsonString(buf);
}

static void
RadsrsJsonFloat(float value)
{
   if ((value != value) || (value > FLT_MAX) || (value < -FLT_MAX))
      fputs("null", stdout);
   else
      fprintf(stdout, "%.9g", value);
}

static unsigned int
RadsrsGetBE16(const unsigned char *value)
{
   return ((unsigned int)value[0] << 8) | (unsigned int)value[1];
}

static const char *
RadsrsRecordTypeName(unsigned char type)
{
   switch (type & 0xf0) {
      case ARGUS_MAR:
         return "management";
      case ARGUS_FAR:
         return "flow";
      case ARGUS_INDEX:
         return "index";
      case ARGUS_NETFLOW:
         return "netflow";
      case ARGUS_EVENT:
         return "event";
      case ARGUS_AFLOW:
         return "aflow";
      case ARGUS_DATASUP:
         return "datasup";
      case ARGUS_ARCHIVAL:
         return "archival";
      default:
         return "unknown";
   }
}

static const char *
RadsrsDsrName(unsigned char type)
{
   switch (type & 0x7f) {
      case ARGUS_TRANSPORT_DSR:
         return "transport";
      case ARGUS_FLOW_DSR:
         return "flow";
      case ARGUS_TIME_DSR:
         return "time";
      case ARGUS_FLOW_HASH_DSR:
         return "flow_hash";
      case ARGUS_METER_DSR:
         return "meter";
      case ARGUS_PSIZE_DSR:
         return "packet_size";
      case ARGUS_ENCAPS_DSR:
         return "encapsulation";
      case ARGUS_NETWORK_DSR:
         return "network";
      case ARGUS_ASN_DSR:
         return "asn";
      case ARGUS_ICMP_DSR:
         return "icmp";
      case ARGUS_VLAN_DSR:
         return "vlan";
      case ARGUS_GRE_DSR:
         return "gre";
      case ARGUS_MAC_DSR:
         return "mac";
      case ARGUS_VXLAN_DSR:
         return "vxlan";
      case ARGUS_MPLS_DSR:
         return "mpls";
      case ARGUS_GENEVE_DSR:
         return "geneve";
      case ARGUS_JITTER_DSR:
         return "jitter";
      case ARGUS_HISTO_DSR:
         return "histogram";
      case ARGUS_IPATTR_DSR:
         return "ip_attributes";
      case ARGUS_DATA_DSR:
         return "data";
      case ARGUS_CONTEXT_DSR:
         return "context";
      case ARGUS_BEHAVIOR_DSR:
         return "behavior";
      case ARGUS_SCORE_DSR:
         return "score";
      case ARGUS_AGR_DSR:
         return "aggregation";
      case ARGUS_COR_DSR:
         return "correlation";
      case ARGUS_COCODE_DSR:
         return "country_code";
      case ARGUS_LABEL_DSR:
         return "label";
      case ARGUS_GEO_DSR:
         return "geo";
      case ARGUS_LOCAL_DSR:
         return "local";
      default:
         return "unknown";
   }
}

static const char *
RadsrsSlotName(int slot)
{
   switch (slot) {
      case ARGUS_TRANSPORT_INDEX:
         return "trans";
      case ARGUS_FLOW_INDEX:
         return "flow";
      case ARGUS_TIME_INDEX:
         return "time";
      case ARGUS_METRIC_INDEX:
         return "metric";
      case ARGUS_AGR_INDEX:
         return "agr";
      case ARGUS_NETWORK_INDEX:
         return "net";
      case ARGUS_VLAN_INDEX:
         return "vlan";
      case ARGUS_MPLS_INDEX:
         return "mpls";
      case ARGUS_JITTER_INDEX:
         return "jitter";
      case ARGUS_IPATTR_INDEX:
         return "ipattr";
      case ARGUS_PSIZE_INDEX:
         return "psize";
      case ARGUS_SRCUSERDATA_INDEX:
         return "suser";
      case ARGUS_DSTUSERDATA_INDEX:
         return "duser";
      case ARGUS_MAC_INDEX:
         return "mac";
      case ARGUS_ICMP_INDEX:
         return "icmp";
      case ARGUS_ENCAPS_INDEX:
         return "encaps";
      case ARGUS_TIME_ADJ_INDEX:
         return "tadj";
      case ARGUS_BEHAVIOR_INDEX:
         return "behavior";
      case ARGUS_COR_INDEX:
         return "cor";
      case ARGUS_COCODE_INDEX:
         return "cocode";
      case ARGUS_LABEL_INDEX:
         return "label";
      case ARGUS_ASN_INDEX:
         return "asn";
      case ARGUS_GEO_INDEX:
         return "geo";
      case ARGUS_LOCAL_INDEX:
         return "local";
      case ARGUS_FLOW_HASH_INDEX:
         return "hash";
      case ARGUS_VXLAN_INDEX:
         return "vxlan";
      case ARGUS_GRE_INDEX:
         return "gre";
      case ARGUS_GENEVE_INDEX:
         return "geneve";
      case ARGUS_SCORE_INDEX:
         return "score";
      case ARGUS_CONTEXT_INDEX:
         return "context";
      default:
         return "unknown";
   }
}

static int
RadsrsDsrSlot(unsigned char type, unsigned char subtype, unsigned char qual)
{
   switch (type & 0x7f) {
      case ARGUS_TRANSPORT_DSR:
         return ARGUS_TRANSPORT_INDEX;
      case ARGUS_FLOW_DSR:
         return ARGUS_FLOW_INDEX;
      case ARGUS_TIME_DSR:
         return ARGUS_TIME_INDEX;
      case ARGUS_FLOW_HASH_DSR:
         return ARGUS_FLOW_HASH_INDEX;
      case ARGUS_METER_DSR:
         return ARGUS_METRIC_INDEX;
      case ARGUS_PSIZE_DSR:
         return ARGUS_PSIZE_INDEX;
      case ARGUS_ENCAPS_DSR:
         return ARGUS_ENCAPS_INDEX;
      case ARGUS_NETWORK_DSR:
         return ARGUS_NETWORK_INDEX;
      case ARGUS_ASN_DSR:
         return ARGUS_ASN_INDEX;
      case ARGUS_ICMP_DSR:
         return ARGUS_ICMP_INDEX;
      case ARGUS_VLAN_DSR:
         return ARGUS_VLAN_INDEX;
      case ARGUS_GRE_DSR:
         return ARGUS_GRE_INDEX;
      case ARGUS_MAC_DSR:
         return ARGUS_MAC_INDEX;
      case ARGUS_VXLAN_DSR:
         return ARGUS_VXLAN_INDEX;
      case ARGUS_MPLS_DSR:
         return ARGUS_MPLS_INDEX;
      case ARGUS_GENEVE_DSR:
         return ARGUS_GENEVE_INDEX;
      case ARGUS_JITTER_DSR:
         return ARGUS_JITTER_INDEX;
      case ARGUS_HISTO_DSR:
         /* Histo shares the correlation index but has no ArgusCanonRecord
          * member, so retain it only in the ordered raw DSR view. */
         return -1;
      case ARGUS_COR_DSR:
         return ARGUS_COR_INDEX;
      case ARGUS_IPATTR_DSR:
         return ARGUS_IPATTR_INDEX;
      case ARGUS_DATA_DSR:
         if (subtype & ARGUS_SRC_DATA)
            return ARGUS_SRCUSERDATA_INDEX;
         if ((subtype & ARGUS_DST_DATA) || (qual & ARGUS_DST_DATA))
            return ARGUS_DSTUSERDATA_INDEX;
         return -1;
      case ARGUS_CONTEXT_DSR:
         return ARGUS_CONTEXT_INDEX;
      case ARGUS_BEHAVIOR_DSR:
         return ARGUS_BEHAVIOR_INDEX;
      case ARGUS_SCORE_DSR:
         return ARGUS_SCORE_INDEX;
      case ARGUS_AGR_DSR:
         return ARGUS_AGR_INDEX;
      case ARGUS_COCODE_DSR:
         return ARGUS_COCODE_INDEX;
      case ARGUS_LABEL_DSR:
         return ARGUS_LABEL_INDEX;
      case ARGUS_GEO_DSR:
         return ARGUS_GEO_INDEX;
      case ARGUS_LOCAL_DSR:
         return ARGUS_LOCAL_INDEX;
      default:
         return -1;
   }
}

static void
RadsrsPrintTime(const struct ArgusTime *time)
{
   fprintf(stdout, "{\"tv_sec\": %d, \"tv_usec\": %d}",
           time->tv_sec, time->tv_usec);
}

static void
RadsrsPrintStatObject(const struct ArgusStatObject *stat)
{
   int i;

   fputs("{\"n\": ", stdout);
   fprintf(stdout, "%d", stat->n);
   fputs(", \"minval\": ", stdout);
   RadsrsJsonFloat(stat->minval);
   fputs(", \"meanval\": ", stdout);
   RadsrsJsonFloat(stat->meanval);
   fputs(", \"stdev\": ", stdout);
   RadsrsJsonFloat(stat->stdev);
   fputs(", \"maxval\": ", stdout);
   RadsrsJsonFloat(stat->maxval);
   fputs(", \"fdist\": [", stdout);
   for (i = 0; i < (int)sizeof(stat->fdist); i++) {
      if (i)
         fputs(", ", stdout);
      fprintf(stdout, "%u", (unsigned int)stat->fdist[i]);
   }
   fputs("]}", stdout);
}

static void
RadsrsPrintDsrHeader(const struct ArgusDSRHeader *hdr)
{
   unsigned int length_words;

   if (hdr->type & ARGUS_IMMEDIATE_DATA)
      length_words = 1;
   else if (hdr->subtype & ARGUS_LEN_16BITS)
      length_words = hdr->argus_dsrvl16.len;
   else
      length_words = hdr->argus_dsrvl8.len;

   fputs("{\"type\": ", stdout);
   fprintf(stdout, "%u", (unsigned int)hdr->type);
   fputs(", \"name\": ", stdout);
   RadsrsJsonString(RadsrsDsrName(hdr->type));
   fputs(", \"subtype\": ", stdout);
   fprintf(stdout, "%u", (unsigned int)hdr->subtype);
   fputs(", \"qualifier\": ", stdout);
   if ((hdr->type & ARGUS_IMMEDIATE_DATA) || (hdr->subtype & ARGUS_LEN_16BITS))
      fputs("null", stdout);
   else
      fprintf(stdout, "%u", (unsigned int)hdr->argus_dsrvl8.qual);
   fputs(", \"length_words\": ", stdout);
   fprintf(stdout, "%u", length_words);
   fputc('}', stdout);
}

static void
RadsrsPrintIPv4(unsigned int value)
{
   struct in_addr addr;
   char text[INET_ADDRSTRLEN];

   addr.s_addr = htonl(value);
   if (inet_ntop(AF_INET, &addr, text, sizeof(text)) == NULL)
      fputs("null", stdout);
   else
      RadsrsJsonString(text);
}

static void
RadsrsPrintIPv6(const unsigned int value[4])
{
   uint32_t address[4];
   char text[INET6_ADDRSTRLEN];
   int i;

   for (i = 0; i < 4; i++)
      address[i] = htonl(value[i]);

   if (inet_ntop(AF_INET6, address, text, sizeof(text)) == NULL)
      fputs("null", stdout);
   else
      RadsrsJsonString(text);
}

static void
RadsrsPrintMac(const unsigned char *address)
{
   char text[18];

   snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned int)address[0], (unsigned int)address[1],
            (unsigned int)address[2], (unsigned int)address[3],
            (unsigned int)address[4], (unsigned int)address[5]);
   RadsrsJsonString(text);
}

static void
RadsrsPrintFlow(const struct ArgusFlow *flow)
{
   unsigned char address_type = flow->hdr.argus_dsrvl8.qual & 0x1f;
   unsigned char subtype = flow->hdr.subtype & 0x3f;

   fputs("{\"struct\": \"ArgusFlow\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&flow->hdr);
   fputs(", \"fields\": {\"address_type\": ", stdout);
   fprintf(stdout, "%u", (unsigned int)address_type);
   fputs(", \"flow_subtype\": ", stdout);
   fprintf(stdout, "%u", (unsigned int)subtype);

   switch (address_type) {
      case ARGUS_TYPE_IPV4:
         fputs(", \"ip_src\": ", stdout);
         if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)
            RadsrsPrintIPv4(flow->frag_flow.ip_src);
         else
            RadsrsPrintIPv4(flow->ip_flow.ip_src);
         fputs(", \"ip_dst\": ", stdout);
         if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)
            RadsrsPrintIPv4(flow->frag_flow.ip_dst);
         else
            RadsrsPrintIPv4(flow->ip_flow.ip_dst);
         fputs(", \"ip_p\": ", stdout);
         if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)
            fprintf(stdout, "%u", (unsigned int)flow->frag_flow.ip_p);
         else
            fprintf(stdout, "%u", (unsigned int)flow->ip_flow.ip_p);

         if (!(flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) &&
             (subtype == ARGUS_FLOW_CLASSIC5TUPLE)) {
            fprintf(stdout, ", \"tp_p\": %u", (unsigned int)flow->ip_flow.tp_p);
            switch (flow->ip_flow.ip_p) {
               case IPPROTO_TCP:
               case IPPROTO_UDP:
                  fprintf(stdout, ", \"sport\": %u, \"dport\": %u",
                          (unsigned int)flow->ip_flow.sport,
                          (unsigned int)flow->ip_flow.dport);
                  break;
               case IPPROTO_ICMP:
                  fprintf(stdout, ", \"icmp_type\": %u, \"icmp_code\": %u",
                          (unsigned int)flow->icmp_flow.type,
                          (unsigned int)flow->icmp_flow.code);
                  fprintf(stdout, ", \"icmp_id\": %u, \"ip_id\": %u",
                          (unsigned int)flow->icmp_flow.id,
                          (unsigned int)flow->icmp_flow.ip_id);
                  break;
               case IPPROTO_ESP:
                  fprintf(stdout, ", \"spi\": %u", flow->esp_flow.spi);
                  break;
            }
            fprintf(stdout, ", \"smask\": %u, \"dmask\": %u",
                    (unsigned int)flow->ip_flow.smask,
                    (unsigned int)flow->ip_flow.dmask);
         }
         break;

      case ARGUS_TYPE_IPV6:
         fputs(", \"ip_src\": ", stdout);
         RadsrsPrintIPv6(flow->ipv6_flow.ip_src);
         fputs(", \"ip_dst\": ", stdout);
         RadsrsPrintIPv6(flow->ipv6_flow.ip_dst);
         fprintf(stdout, ", \"ip_p\": %u, \"flow\": %u",
                 (unsigned int)flow->ipv6_flow.ip_p,
                 (unsigned int)flow->ipv6_flow.flow);
         if (subtype == ARGUS_FLOW_CLASSIC5TUPLE) {
            switch (flow->ipv6_flow.ip_p) {
               case IPPROTO_TCP:
               case IPPROTO_UDP:
                  fprintf(stdout, ", \"sport\": %u, \"dport\": %u",
                          (unsigned int)flow->ipv6_flow.sport,
                          (unsigned int)flow->ipv6_flow.dport);
                  break;
               case IPPROTO_ICMPV6:
                  fprintf(stdout, ", \"icmp_type\": %u, \"icmp_code\": %u, \"icmp_id\": %u",
                          (unsigned int)flow->icmpv6_flow.type,
                          (unsigned int)flow->icmpv6_flow.code,
                          (unsigned int)flow->icmpv6_flow.id);
                  break;
            }
         }
         fprintf(stdout, ", \"smask\": %u, \"dmask\": %u",
                 (unsigned int)flow->ipv6_flow.smask,
                 (unsigned int)flow->ipv6_flow.dmask);
         break;

      case ARGUS_TYPE_ETHER:
         fputs(", \"ether_shost\": ", stdout);
         RadsrsPrintMac((const unsigned char *)flow->mac_flow.mac_union.ether.ehdr.ether_shost);
         fputs(", \"ether_dhost\": ", stdout);
         RadsrsPrintMac((const unsigned char *)flow->mac_flow.mac_union.ether.ehdr.ether_dhost);
         fprintf(stdout, ", \"ether_type\": %u, \"dsap\": %u, \"ssap\": %u",
                 (unsigned int)flow->mac_flow.mac_union.ether.ehdr.ether_type,
                 (unsigned int)flow->mac_flow.mac_union.ether.dsap,
                 (unsigned int)flow->mac_flow.mac_union.ether.ssap);
         break;

      case ARGUS_TYPE_WLAN:
         fputs(", \"dhost\": ", stdout);
         RadsrsPrintMac(flow->wlan_flow.dhost);
         fputs(", \"shost\": ", stdout);
         RadsrsPrintMac(flow->wlan_flow.shost);
         fputs(", \"bssid\": ", stdout);
         RadsrsPrintMac(flow->wlan_flow.bssid);
         fputs(", \"ssid_base64\": ", stdout);
         RadsrsJsonBase64((const unsigned char *)flow->wlan_flow.ssid,
                          sizeof(flow->wlan_flow.ssid));
         break;

      case ARGUS_TYPE_ARP:
         fprintf(stdout, ", \"hrd\": %u, \"pro\": %u, \"hln\": %u, \"pln\": %u, \"op\": %u",
                 (unsigned int)flow->arp_flow.hrd,
                 (unsigned int)flow->arp_flow.pro,
                 (unsigned int)flow->arp_flow.hln,
                 (unsigned int)flow->arp_flow.pln,
                 (unsigned int)flow->arp_flow.op);
         fputs(", \"arp_spa\": ", stdout);
         RadsrsPrintIPv4(flow->arp_flow.arp_spa);
         fputs(", \"arp_tpa\": ", stdout);
         RadsrsPrintIPv4(flow->arp_flow.arp_tpa);
         fputs(", \"haddr_base64\": ", stdout);
         RadsrsJsonBase64((const unsigned char *)&flow->arp_flow.haddr,
                          sizeof(flow->arp_flow.haddr));
         break;

      case ARGUS_TYPE_RARP:
         fprintf(stdout, ", \"hrd\": %u, \"pro\": %u, \"hln\": %u, \"pln\": %u, \"op\": %u",
                 (unsigned int)flow->rarp_flow.hrd,
                 (unsigned int)flow->rarp_flow.pro,
                 (unsigned int)flow->rarp_flow.hln,
                 (unsigned int)flow->rarp_flow.pln,
                 (unsigned int)flow->rarp_flow.op);
         fputs(", \"arp_tpa\": ", stdout);
         RadsrsPrintIPv4(flow->rarp_flow.arp_tpa);
         fputs(", \"shaddr_base64\": ", stdout);
         RadsrsJsonBase64((const unsigned char *)&flow->rarp_flow.shaddr,
                          sizeof(flow->rarp_flow.shaddr));
         fputs(", \"dhaddr_base64\": ", stdout);
         RadsrsJsonBase64((const unsigned char *)&flow->rarp_flow.dhaddr,
                          sizeof(flow->rarp_flow.dhaddr));
         break;

      default:
         fputs(", \"decoded_union\": false", stdout);
         break;
   }
   fputs("}}", stdout);
}

static void
RadsrsPrintTransport(const struct ArgusTransportStruct *trans)
{
   fputs("{\"struct\": \"ArgusTransportStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&trans->hdr);
   fputs(", \"srcid_base64\": ", stdout);
   RadsrsJsonBase64((const unsigned char *)&trans->srcid, sizeof(trans->srcid));
   fputs(", \"seqnum\": ", stdout);
   fprintf(stdout, "%u", trans->seqnum);
   fputc('}', stdout);
}

static void
RadsrsPrintTimeObject(const struct ArgusTimeObject *time)
{
   fputs("{\"struct\": \"ArgusTimeObject\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&time->hdr);
   fputs(", \"src\": {\"start\": ", stdout);
   RadsrsPrintTime(&time->src.start);
   fputs(", \"end\": ", stdout);
   RadsrsPrintTime(&time->src.end);
   fputs("}, \"dst\": {\"start\": ", stdout);
   RadsrsPrintTime(&time->dst.start);
   fputs(", \"end\": ", stdout);
   RadsrsPrintTime(&time->dst.end);
   fputs("}}", stdout);
}

static void
RadsrsPrintMetric(const struct ArgusMetricStruct *metric)
{
   fputs("{\"struct\": \"ArgusMetricStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&metric->hdr);
   fputs(", \"src\": {\"pkts\": ", stdout);
   RadsrsJsonInt64(metric->src.pkts);
   fputs(", \"bytes\": ", stdout);
   RadsrsJsonInt64(metric->src.bytes);
   fputs(", \"appbytes\": ", stdout);
   RadsrsJsonInt64(metric->src.appbytes);
   fputs("}, \"dst\": {\"pkts\": ", stdout);
   RadsrsJsonInt64(metric->dst.pkts);
   fputs(", \"bytes\": ", stdout);
   RadsrsJsonInt64(metric->dst.bytes);
   fputs(", \"appbytes\": ", stdout);
   RadsrsJsonInt64(metric->dst.appbytes);
   fputs("}}", stdout);
}

static void
RadsrsPrintAggregation(const struct ArgusAgrStruct *agr)
{
   fputs("{\"struct\": \"ArgusAgrStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&agr->hdr);
   fprintf(stdout, ", \"count\": %u, \"laststartime\": ", agr->count);
   RadsrsPrintTime(&agr->laststartime);
   fputs(", \"lasttime\": ", stdout);
   RadsrsPrintTime(&agr->lasttime);
   fputs(", \"act\": ", stdout);
   RadsrsPrintStatObject(&agr->act);
   fputs(", \"idle\": ", stdout);
   RadsrsPrintStatObject(&agr->idle);
   fputc('}', stdout);
}

static void
RadsrsPrintTcpMetrics(const struct ArgusTCPObjectMetrics *metrics)
{
   fputs("{\"lasttime\": ", stdout);
   RadsrsPrintTime(&metrics->lasttime);
   fprintf(stdout, ", \"status\": %u, \"seqbase\": %u, \"seq\": %u, \"ack\": %u",
           metrics->status, metrics->seqbase, metrics->seq, metrics->ack);
   fprintf(stdout, ", \"winnum\": %u, \"bytes\": %u, \"retrans\": %u, \"ackbytes\": %u, \"winbytes\": %u",
           metrics->winnum, metrics->bytes, metrics->retrans,
           metrics->ackbytes, metrics->winbytes);
   fprintf(stdout, ", \"win\": %u, \"flags\": %u, \"winshift\": %u, \"maxseg\": %u}",
           (unsigned int)metrics->win, (unsigned int)metrics->flags,
           (unsigned int)metrics->winshift, (unsigned int)metrics->maxseg);
}

static void
RadsrsPrintNetwork(const struct ArgusNetworkStruct *net)
{
   unsigned char subtype = net->hdr.subtype & 0x3f;

   fputs("{\"struct\": \"ArgusNetworkStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&net->hdr);
   fputs(", \"fields\": {", stdout);

   switch (subtype) {
      case ARGUS_TCP_INIT:
      case ARGUS_TCP_STATUS:
      case ARGUS_TCP_PERF: {
         const struct ArgusTCPObject *tcp = &net->net_union.tcp;

         fprintf(stdout, "\"status\": %u, \"state\": %u, \"options\": %u",
                 tcp->status, tcp->state, tcp->options);
         fprintf(stdout, ", \"synAckuSecs\": %u, \"ackDatauSecs\": %u",
                 tcp->synAckuSecs, tcp->ackDatauSecs);
         fputs(", \"src\": ", stdout);
         RadsrsPrintTcpMetrics(&tcp->src);
         fputs(", \"dst\": ", stdout);
         RadsrsPrintTcpMetrics(&tcp->dst);
         break;
      }

      case ARGUS_NETWORK_SUBTYPE_FRAG:
         fprintf(stdout, "\"fragnum\": %u, \"frag_id\": %u, \"totlen\": %u, \"currlen\": %u, \"maxfraglen\": %u",
                 net->net_union.frag.fragnum, net->net_union.frag.frag_id,
                 (unsigned int)net->net_union.frag.totlen,
                 (unsigned int)net->net_union.frag.currlen,
                 (unsigned int)net->net_union.frag.maxfraglen);
         break;

      default:
         fputs("\"decoded_union\": false", stdout);
         break;
   }
   fputs("}}", stdout);
}

static void
RadsrsPrintPacketSize(const struct ArgusPacketSizeStruct *psize)
{
   int i;

   fputs("{\"struct\": \"ArgusPacketSizeStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&psize->hdr);
   fprintf(stdout, ", \"src\": {\"psizemin\": %u, \"psizemax\": %u, \"psize\": [",
           (unsigned int)psize->src.psizemin, (unsigned int)psize->src.psizemax);
   for (i = 0; i < (int)sizeof(psize->src.psize); i++) {
      if (i)
         fputs(", ", stdout);
      fprintf(stdout, "%u", (unsigned int)psize->src.psize[i]);
   }
   fprintf(stdout, "]}, \"dst\": {\"psizemin\": %u, \"psizemax\": %u, \"psize\": [",
           (unsigned int)psize->dst.psizemin, (unsigned int)psize->dst.psizemax);
   for (i = 0; i < (int)sizeof(psize->dst.psize); i++) {
      if (i)
         fputs(", ", stdout);
      fprintf(stdout, "%u", (unsigned int)psize->dst.psize[i]);
   }
   fputs("]}}", stdout);
}

static void
RadsrsPrintVlan(const struct ArgusVlanStruct *vlan)
{
   fputs("{\"struct\": \"ArgusVlanStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&vlan->hdr);
   fprintf(stdout, ", \"sid\": %u, \"did\": %u}",
           (unsigned int)vlan->sid, (unsigned int)vlan->did);
}

static void
RadsrsPrintMpls(const struct ArgusMplsStruct *mpls)
{
   fputs("{\"struct\": \"ArgusMplsStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&mpls->hdr);
   fprintf(stdout, ", \"slabel\": %u, \"dlabel\": %u}", mpls->slabel, mpls->dlabel);
}

static void
RadsrsPrintJitter(const struct ArgusJitterStruct *jitter)
{
   fputs("{\"struct\": \"ArgusJitterStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&jitter->hdr);
   fputs(", \"src\": {\"act\": ", stdout);
   RadsrsPrintStatObject(&jitter->src.act);
   fputs(", \"idle\": ", stdout);
   RadsrsPrintStatObject(&jitter->src.idle);
   fputs("}, \"dst\": {\"act\": ", stdout);
   RadsrsPrintStatObject(&jitter->dst.act);
   fputs(", \"idle\": ", stdout);
   RadsrsPrintStatObject(&jitter->dst.idle);
   fputs("}}", stdout);
}

static void
RadsrsPrintIpAttrObject(const struct ArgusIPAttrObject *attr)
{
   fprintf(stdout, "{\"ttl\": %u, \"tos\": %u, \"ip_id\": %u, \"options\": %u}",
           (unsigned int)attr->ttl, (unsigned int)attr->tos,
           (unsigned int)attr->ip_id, attr->options);
}

static void
RadsrsPrintIpAttr(const struct ArgusIPAttrStruct *attr)
{
   fputs("{\"struct\": \"ArgusIPAttrStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&attr->hdr);
   fputs(", \"src\": ", stdout);
   RadsrsPrintIpAttrObject(&attr->src);
   fputs(", \"dst\": ", stdout);
   RadsrsPrintIpAttrObject(&attr->dst);
   fputc('}', stdout);
}

static void
RadsrsPrintMacStruct(const struct ArgusMacStruct *mac)
{
   const struct ArgusEtherMacFlow *ether = &mac->mac.mac_union.ether;

   fputs("{\"struct\": \"ArgusMacStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&mac->hdr);
   fputs(", \"ether_shost\": ", stdout);
   RadsrsPrintMac((const unsigned char *)ether->ehdr.ether_shost);
   fputs(", \"ether_dhost\": ", stdout);
   RadsrsPrintMac((const unsigned char *)ether->ehdr.ether_dhost);
   fprintf(stdout, ", \"ether_type\": %u, \"dsap\": %u, \"ssap\": %u}",
           (unsigned int)ether->ehdr.ether_type, (unsigned int)ether->dsap,
           (unsigned int)ether->ssap);
}

static void
RadsrsPrintIcmp(const struct ArgusIcmpStruct *icmp)
{
   fputs("{\"struct\": \"ArgusIcmpStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&icmp->hdr);
   fprintf(stdout, ", \"icmp_type\": %u, \"icmp_code\": %u, \"iseq\": %u",
           (unsigned int)icmp->icmp_type, (unsigned int)icmp->icmp_code,
           (unsigned int)icmp->iseq);
   fputs(", \"osrcaddr\": ", stdout);
   RadsrsPrintIPv4(icmp->osrcaddr);
   fputs(", \"odstaddr\": ", stdout);
   RadsrsPrintIPv4(icmp->odstaddr);
   fputs(", \"isrcaddr\": ", stdout);
   RadsrsPrintIPv4(icmp->isrcaddr);
   fputs(", \"idstaddr\": ", stdout);
   RadsrsPrintIPv4(icmp->idstaddr);
   fputs(", \"igwaddr\": ", stdout);
   RadsrsPrintIPv4(icmp->igwaddr);
   fputc('}', stdout);
}

static void
RadsrsPrintEncaps(const struct ArgusEncapsStruct *encaps)
{
   fputs("{\"struct\": \"ArgusEncapsStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&encaps->hdr);
   fprintf(stdout, ", \"src\": %u, \"dst\": %u, \"slen\": %u, \"dlen\": %u",
           encaps->src, encaps->dst, (unsigned int)encaps->slen,
           (unsigned int)encaps->dlen);
   fputs(", \"sbuf_base64\": ", stdout);
   if ((encaps->sbuf == NULL) || (encaps->slen == 0))
      fputs("null", stdout);
   else
      RadsrsJsonBase64(encaps->sbuf, encaps->slen);
   fputs(", \"dbuf_base64\": ", stdout);
   if ((encaps->dbuf == NULL) || (encaps->dlen == 0))
      fputs("null", stdout);
   else
      RadsrsJsonBase64(encaps->dbuf, encaps->dlen);
   fputc('}', stdout);
}

static void
RadsrsPrintBehavior(const struct ArgusBehaviorStruct *behavior)
{
   fputs("{\"struct\": \"ArgusBehaviorStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&behavior->hdr);
   fprintf(stdout, ", \"src_n_strokes\": %d, \"dst_n_strokes\": %d}",
           behavior->keyStroke.src.n_strokes, behavior->keyStroke.dst.n_strokes);
}

static void
RadsrsPrintCorrelation(const struct ArgusCorrelateStruct *cor)
{
   fputs("{\"struct\": \"ArgusCorrelateStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&cor->hdr);
   fputs(", \"srcid_base64\": ", stdout);
   RadsrsJsonBase64((const unsigned char *)&cor->metrics.srcid, sizeof(cor->metrics.srcid));
   fprintf(stdout, ", \"deltaDur\": %d, \"deltaStart\": %d, \"deltaLast\": %d",
           cor->metrics.deltaDur, cor->metrics.deltaStart, cor->metrics.deltaLast);
   fprintf(stdout, ", \"deltaSrcPkts\": %d, \"deltaDstPkts\": %d}",
           cor->metrics.deltaSrcPkts, cor->metrics.deltaDstPkts);
}

static void
RadsrsPrintCountryCode(const struct ArgusCountryCodeStruct *cocode)
{
   fputs("{\"struct\": \"ArgusCountryCodeStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&cocode->hdr);
   fputs(", \"src\": ", stdout);
   RadsrsJsonStringN((const unsigned char *)cocode->src, sizeof(cocode->src));
   fputs(", \"dst\": ", stdout);
   RadsrsJsonStringN((const unsigned char *)cocode->dst, sizeof(cocode->dst));
   fputc('}', stdout);
}

static void
RadsrsPrintAsn(const struct ArgusAsnStruct *asn)
{
   fputs("{\"struct\": \"ArgusAsnStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&asn->hdr);
   fprintf(stdout, ", \"src_as\": %u, \"dst_as\": %u, \"inode_as\": %u}",
           asn->src_as, asn->dst_as, asn->inode_as);
}

static void
RadsrsPrintGeoCoordinates(const struct ArgusCoordinates *coordinates)
{
   fputs("{\"lat\": ", stdout);
   RadsrsJsonFloat(coordinates->lat);
   fputs(", \"lon\": ", stdout);
   RadsrsJsonFloat(coordinates->lon);
   fputc('}', stdout);
}

static void
RadsrsPrintGeo(const struct ArgusGeoLocationStruct *geo)
{
   fputs("{\"struct\": \"ArgusGeoLocationStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&geo->hdr);
   fputs(", \"src\": ", stdout);
   RadsrsPrintGeoCoordinates(&geo->src);
   fputs(", \"dst\": ", stdout);
   RadsrsPrintGeoCoordinates(&geo->dst);
   fputs(", \"inode\": ", stdout);
   RadsrsPrintGeoCoordinates(&geo->inode);
   fputc('}', stdout);
}

static void
RadsrsPrintLocal(const struct ArgusNetspatialStruct *local)
{
   fputs("{\"struct\": \"ArgusNetspatialStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&local->hdr);
   fprintf(stdout, ", \"status\": %u, \"sloc\": %d, \"dloc\": %d, \"sorg\": %u, \"dorg\": %u}",
           (unsigned int)local->status, (int)local->sloc, (int)local->dloc,
           (unsigned int)local->sorg, (unsigned int)local->dorg);
}

static void
RadsrsPrintHash(const struct ArgusFlowHashStruct *hash)
{
   fputs("{\"struct\": \"ArgusFlowHashStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&hash->hdr);
   fprintf(stdout, ", \"hash\": %u, \"ind\": %u}", hash->hash, hash->ind);
}

static void
RadsrsPrintVxlan(const struct ArgusVxLanStruct *vxlan)
{
   fputs("{\"struct\": \"ArgusVxLanStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&vxlan->hdr);
   fprintf(stdout, ", \"svnid\": %u, \"dvnid\": %u, \"tflow\": ",
           vxlan->svnid, vxlan->dvnid);
   RadsrsPrintFlow(&vxlan->tflow);
   fputc('}', stdout);
}

static void
RadsrsPrintGre(const struct ArgusGreStruct *gre)
{
   fputs("{\"struct\": \"ArgusGreStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&gre->hdr);
   fprintf(stdout, ", \"flags\": %u, \"proto\": %u, \"tflow\": ",
           (unsigned int)gre->flags, (unsigned int)gre->proto);
   RadsrsPrintFlow(&gre->tflow);
   fputc('}', stdout);
}

static void
RadsrsPrintGeneve(const struct ArgusGeneveStruct *geneve)
{
   fputs("{\"struct\": \"ArgusGeneveStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&geneve->hdr);
   fprintf(stdout, ", \"ver_opt\": %u, \"flags\": %u, \"ptype\": %u, \"vni\": %u, \"tflow\": ",
           (unsigned int)geneve->ver_opt, (unsigned int)geneve->flags,
           (unsigned int)geneve->ptype, geneve->vni);
   RadsrsPrintFlow(&geneve->tflow);
   fputc('}', stdout);
}

static void
RadsrsPrintScore(const struct ArgusScoreStruct *score)
{
   int i;

   fputs("{\"struct\": \"ArgusScoreStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&score->hdr);
   fputs(", \"values\": [", stdout);
   for (i = 0; i < (int)sizeof(score->behvScore.values); i++) {
      if (i)
         fputs(", ", stdout);
      fprintf(stdout, "%d", (int)(unsigned char)score->behvScore.values[i]);
   }
   fputs("]}", stdout);
}

static void
RadsrsPrintContext(const struct ArgusContextStruct *context)
{
   fputs("{\"struct\": \"ArgusContextStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&context->hdr);
   fputs(", \"ctime\": ", stdout);
   RadsrsPrintTime(&context->ctime);
   fputc('}', stdout);
}

static void
RadsrsPrintData(const struct ArgusDataStruct *data)
{
   fputs("{\"struct\": \"ArgusDataStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&data->hdr);
   fprintf(stdout, ", \"size\": %u, \"count\": %u}",
           (unsigned int)data->size, (unsigned int)data->count);
}

static void
RadsrsPrintLabel(const struct ArgusLabelStruct *label)
{
   fputs("{\"struct\": \"ArgusLabelStruct\", \"header\": ", stdout);
   RadsrsPrintDsrHeader(&label->hdr);
   fputs(", \"label\": ", stdout);
   RadsrsJsonString(label->l_un.label);
   fputc('}', stdout);
}

static void
RadsrsPrintCanonicalSlot(int slot, const struct ArgusDSRHeader *dsr)
{
   switch (slot) {
      case ARGUS_TRANSPORT_INDEX:
         RadsrsPrintTransport((const struct ArgusTransportStruct *)dsr);
         break;
      case ARGUS_FLOW_INDEX:
         RadsrsPrintFlow((const struct ArgusFlow *)dsr);
         break;
      case ARGUS_TIME_INDEX:
         RadsrsPrintTimeObject((const struct ArgusTimeObject *)dsr);
         break;
      case ARGUS_METRIC_INDEX:
         RadsrsPrintMetric((const struct ArgusMetricStruct *)dsr);
         break;
      case ARGUS_AGR_INDEX:
         RadsrsPrintAggregation((const struct ArgusAgrStruct *)dsr);
         break;
      case ARGUS_NETWORK_INDEX:
         RadsrsPrintNetwork((const struct ArgusNetworkStruct *)dsr);
         break;
      case ARGUS_VLAN_INDEX:
         RadsrsPrintVlan((const struct ArgusVlanStruct *)dsr);
         break;
      case ARGUS_MPLS_INDEX:
         RadsrsPrintMpls((const struct ArgusMplsStruct *)dsr);
         break;
      case ARGUS_JITTER_INDEX:
         RadsrsPrintJitter((const struct ArgusJitterStruct *)dsr);
         break;
      case ARGUS_IPATTR_INDEX:
         RadsrsPrintIpAttr((const struct ArgusIPAttrStruct *)dsr);
         break;
      case ARGUS_PSIZE_INDEX:
         RadsrsPrintPacketSize((const struct ArgusPacketSizeStruct *)dsr);
         break;
      case ARGUS_SRCUSERDATA_INDEX:
      case ARGUS_DSTUSERDATA_INDEX:
         RadsrsPrintData((const struct ArgusDataStruct *)dsr);
         break;
      case ARGUS_MAC_INDEX:
         RadsrsPrintMacStruct((const struct ArgusMacStruct *)dsr);
         break;
      case ARGUS_ICMP_INDEX:
         RadsrsPrintIcmp((const struct ArgusIcmpStruct *)dsr);
         break;
      case ARGUS_ENCAPS_INDEX:
         RadsrsPrintEncaps((const struct ArgusEncapsStruct *)dsr);
         break;
      case ARGUS_BEHAVIOR_INDEX:
         RadsrsPrintBehavior((const struct ArgusBehaviorStruct *)dsr);
         break;
      case ARGUS_COR_INDEX:
         RadsrsPrintCorrelation((const struct ArgusCorrelateStruct *)dsr);
         break;
      case ARGUS_COCODE_INDEX:
         RadsrsPrintCountryCode((const struct ArgusCountryCodeStruct *)dsr);
         break;
      case ARGUS_LABEL_INDEX:
         RadsrsPrintLabel((const struct ArgusLabelStruct *)dsr);
         break;
      case ARGUS_ASN_INDEX:
         RadsrsPrintAsn((const struct ArgusAsnStruct *)dsr);
         break;
      case ARGUS_GEO_INDEX:
         RadsrsPrintGeo((const struct ArgusGeoLocationStruct *)dsr);
         break;
      case ARGUS_LOCAL_INDEX:
         RadsrsPrintLocal((const struct ArgusNetspatialStruct *)dsr);
         break;
      case ARGUS_FLOW_HASH_INDEX:
         RadsrsPrintHash((const struct ArgusFlowHashStruct *)dsr);
         break;
      case ARGUS_VXLAN_INDEX:
         RadsrsPrintVxlan((const struct ArgusVxLanStruct *)dsr);
         break;
      case ARGUS_GRE_INDEX:
         RadsrsPrintGre((const struct ArgusGreStruct *)dsr);
         break;
      case ARGUS_GENEVE_INDEX:
         RadsrsPrintGeneve((const struct ArgusGeneveStruct *)dsr);
         break;
      case ARGUS_SCORE_INDEX:
         RadsrsPrintScore((const struct ArgusScoreStruct *)dsr);
         break;
      case ARGUS_CONTEXT_INDEX:
         RadsrsPrintContext((const struct ArgusContextStruct *)dsr);
         break;
      default:
         fputs("{\"struct\": \"unsupported\", \"header\": ", stdout);
         RadsrsPrintDsrHeader(dsr);
         fputc('}', stdout);
         break;
   }
}

static void
RadsrsPrintManagement(const struct ArgusRecordStruct *argus)
{
   const struct ArgusRecord *record = (const struct ArgusRecord *)argus->dsrs[ARGUS_MAR_INDEX];
   const struct ArgusMarStruct *mar;

   if (record == NULL) {
      fputs("null", stdout);
      return;
   }

   mar = &record->argus_mar;
   fputs("{\"struct\": \"ArgusMarStruct\", \"status\": ", stdout);
   fprintf(stdout, "%u, \"argusid\": %u, \"localnet\": %u, \"netmask\": %u",
           mar->status, mar->argusid, mar->localnet, mar->netmask);
   fprintf(stdout, ", \"nextMrSequenceNum\": %u, \"startime\": ",
           mar->nextMrSequenceNum);
   RadsrsPrintTime(&mar->startime);
   fputs(", \"now\": ", stdout);
   RadsrsPrintTime(&mar->now);
   fprintf(stdout, ", \"major_version\": %u, \"minor_version\": %u",
           (unsigned int)mar->major_version, (unsigned int)mar->minor_version);
   fprintf(stdout, ", \"interfaceType\": %u, \"interfaceStatus\": %u",
           (unsigned int)mar->interfaceType, (unsigned int)mar->interfaceStatus);
   fprintf(stdout, ", \"reportInterval\": %u, \"argusMrInterval\": %u",
           (unsigned int)mar->reportInterval, (unsigned int)mar->argusMrInterval);
   fputs(", \"pktsRcvd\": ", stdout);
   RadsrsJsonUInt64(mar->pktsRcvd);
   fputs(", \"bytesRcvd\": ", stdout);
   RadsrsJsonUInt64(mar->bytesRcvd);
   fprintf(stdout, ", \"interfaces\": %u, \"fallow\": %u, \"records\": %u, \"flows\": %u",
           mar->interfaces, mar->fallow, mar->records, mar->flows);
   fprintf(stdout, ", \"dropped\": %u, \"queue\": %u, \"output\": %u, \"clients\": %u",
           mar->dropped, mar->queue, mar->output, mar->clients);
   fprintf(stdout, ", \"bufs\": %u, \"bytes\": %u, \"suserlen\": %u, \"duserlen\": %u",
           mar->bufs, mar->bytes, (unsigned int)mar->suserlen,
           (unsigned int)mar->duserlen);
   fprintf(stdout, ", \"source_id_value\": %u, \"record_len\": %u}",
           mar->value, mar->record_len);
}

static void
RadsrsPrintCanonical(const struct ArgusRecordStruct *argus, int level)
{
   int slot;
   int first = 1;

   fputs("{\n", stdout);
   if ((argus->hdr.type & 0xf0) == ARGUS_MAR) {
      RadsrsIndent(level + 1);
      fputs("\"management\": ", stdout);
      RadsrsPrintManagement(argus);
      fputc('\n', stdout);
   } else {
      for (slot = 0; slot < ARGUSMAXDSRTYPE; slot++) {
         if (argus->dsrs[slot] == NULL)
            continue;

         if (!first)
            fputs(",\n", stdout);
         RadsrsIndent(level + 1);
         RadsrsJsonString(RadsrsSlotName(slot));
         fputs(": ", stdout);
         RadsrsPrintCanonicalSlot(slot, argus->dsrs[slot]);
         first = 0;
      }
      if (!first)
         fputc('\n', stdout);
   }
   RadsrsIndent(level);
   fputc('}', stdout);
}

static void
RadsrsPrintRawDsr(const unsigned char *dsr, size_t offset, size_t length,
                  unsigned int ordinal, int level)
{
   unsigned char type = dsr[0];
   unsigned char subtype = dsr[1];
   unsigned char qual = 0;
   int slot;

   if (!(type & ARGUS_IMMEDIATE_DATA) && !(subtype & ARGUS_LEN_16BITS))
      qual = dsr[2];

   slot = RadsrsDsrSlot(type, subtype, qual);
   RadsrsIndent(level);
   fputs("{\n", stdout);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"ordinal\": %u,\n", ordinal);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"offset_bytes\": %lu,\n", (unsigned long)offset);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"type_raw\": %u,\n", (unsigned int)type);
   RadsrsIndent(level + 1);
   fputs("\"name\": ", stdout);
   RadsrsJsonString(RadsrsDsrName(type));
   fputs(",\n", stdout);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"subtype_raw\": %u,\n", (unsigned int)subtype);
   RadsrsIndent(level + 1);
   fputs("\"encoding\": ", stdout);
   if (type & ARGUS_IMMEDIATE_DATA)
      RadsrsJsonString("immediate");
   else if (subtype & ARGUS_LEN_16BITS)
      RadsrsJsonString("tlv16");
   else
      RadsrsJsonString("tlv8");
   fputs(",\n", stdout);
   RadsrsIndent(level + 1);
   fputs("\"qualifier\": ", stdout);
   if ((type & ARGUS_IMMEDIATE_DATA) || (subtype & ARGUS_LEN_16BITS))
      fputs("null", stdout);
   else
      fprintf(stdout, "%u", (unsigned int)qual);
   fputs(",\n", stdout);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"length_words\": %lu,\n", (unsigned long)(length / 4));
   RadsrsIndent(level + 1);
   fputs("\"canonical_slot\": ", stdout);
   if (slot < 0)
      fputs("null", stdout);
   else
      RadsrsJsonString(RadsrsSlotName(slot));
   fputs(",\n", stdout);
   RadsrsIndent(level + 1);
   fputs("\"raw_base64\": ", stdout);
   RadsrsJsonBase64(dsr, length);
   fputc('\n', stdout);
   RadsrsIndent(level);
   fputc('}', stdout);
}

static void
RadsrsPrintMalformedTail(const unsigned char *data, size_t offset,
                         size_t length, unsigned int ordinal, const char *message,
                         int level)
{
   RadsrsIndent(level);
   fputs("{\n", stdout);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"ordinal\": %u,\n", ordinal);
   RadsrsIndent(level + 1);
   fprintf(stdout, "\"offset_bytes\": %lu,\n", (unsigned long)offset);
   RadsrsIndent(level + 1);
   fputs("\"parse_error\": ", stdout);
   RadsrsJsonString(message);
   fputs(",\n", stdout);
   RadsrsIndent(level + 1);
   fputs("\"raw_base64\": ", stdout);
   RadsrsJsonBase64(data, length);
   fputc('\n', stdout);
   RadsrsIndent(level);
   fputc('}', stdout);
}

static void
RadsrsPrintRawDsrs(const unsigned char *raw, size_t raw_length, int level)
{
   size_t offset = sizeof(struct ArgusRecordHeader);
   unsigned int ordinal = 0;
   int first = 1;

   fputs("[\n", stdout);
   while (offset < raw_length) {
      const unsigned char *dsr = raw + offset;
      size_t remaining = raw_length - offset;
      size_t length;
      unsigned int words;

      if (remaining < 4) {
         if (!first)
            fputs(",\n", stdout);
         RadsrsPrintMalformedTail(dsr, offset, remaining, ordinal,
                                  "truncated DSR header", level + 1);
         first = 0;
         break;
      }

      if (dsr[0] & ARGUS_IMMEDIATE_DATA)
         words = 1;
      else if (dsr[1] & ARGUS_LEN_16BITS)
         words = RadsrsGetBE16(dsr + 2);
      else
         words = dsr[3];

      length = (size_t)words * 4;
      if ((words == 0) || (length < 4) || (length > remaining)) {
         if (!first)
            fputs(",\n", stdout);
         RadsrsPrintMalformedTail(dsr, offset, remaining, ordinal,
                                  "invalid DSR length", level + 1);
         first = 0;
         break;
      }

      if (!first)
         fputs(",\n", stdout);
      RadsrsPrintRawDsr(dsr, offset, length, ordinal, level + 1);
      first = 0;
      ordinal++;
      offset += length;
   }
   if (!first)
      fputc('\n', stdout);
   RadsrsIndent(level);
   fputc(']', stdout);
}

const char *
ArgusRadsrsRecordFidelity(const struct ArgusRecordStruct *argus,
                          const unsigned char *raw, size_t raw_length)
{
   int source_type;
   unsigned int version;

   if ((raw == NULL) || (raw_length < sizeof(struct ArgusRecordHeader)))
      return "unavailable";

   version = raw[0] & ARGUS_VERSION_MASK;
   if ((version != ARGUS_VERSION_3) && (version != ARGUS_VERSION_5))
      return "derived_or_legacy";

   if ((argus == NULL) || (argus->input == NULL))
      return "derived_current_format";

   source_type = argus->input->type & ARGUS_DATA_TYPE;
   if ((source_type == ARGUS_DATA_SOURCE) || (source_type == ARGUS_DOMAIN_SOURCE))
      return "exact_native_v3_v5";

   return "derived_current_format";
}

int
ArgusRadsrsGetRawRecord(const struct ArgusRecordStruct *argus,
                        const unsigned char **raw, size_t *raw_length)
{
   const struct ArgusInput *input;
   size_t length;

   *raw = NULL;
   *raw_length = 0;
   if ((argus == NULL) || ((input = argus->input) == NULL) ||
       (input->ArgusOriginal == NULL))
      return 0;

   length = (size_t)RadsrsGetBE16((const unsigned char *)input->ArgusOriginal + 2) * 4;
   if ((length < sizeof(struct ArgusRecordHeader)) ||
       (length >= sizeof(input->ArgusOriginalBuffer)))
      return 0;

   *raw = (const unsigned char *)input->ArgusOriginal;
   *raw_length = length;
   return 1;
}

static void
RadsrsPrintRecord(const struct ArgusRecordStruct *argus, unsigned long sequence)
{
   const unsigned char *raw = NULL;
   size_t raw_length = 0;
   int have_raw;
   unsigned char type = argus->hdr.type;
   unsigned char cause = argus->hdr.cause;
   unsigned int length_words = argus->hdr.len;

   have_raw = ArgusRadsrsGetRawRecord(argus, &raw, &raw_length);
   if (have_raw) {
      type = raw[0];
      cause = raw[1];
      length_words = RadsrsGetBE16(raw + 2);
   }

   /* RFC 7464 JSON text sequence framing keeps pretty records stream-safe. */
   fputc(0x1e, stdout);
   fputs("{\n", stdout);
   RadsrsIndent(1);
   fputs("\"schema\": ", stdout);
   RadsrsJsonString(RADSRS_SCHEMA);
   fputs(",\n", stdout);
   RadsrsIndent(1);
   fprintf(stdout, "\"sequence\": %lu,\n", sequence);
   RadsrsIndent(1);
   fputs("\"fidelity\": ", stdout);
   RadsrsJsonString(ArgusRadsrsRecordFidelity(argus, raw, raw_length));
   fputs(",\n", stdout);
   RadsrsIndent(1);
   fputs("\"record\": {\n", stdout);
   RadsrsIndent(2);
   fprintf(stdout, "\"type_raw\": %u,\n", (unsigned int)type);
   RadsrsIndent(2);
   fputs("\"type\": ", stdout);
   RadsrsJsonString(RadsrsRecordTypeName(type));
   fputs(",\n", stdout);
   RadsrsIndent(2);
   fprintf(stdout, "\"version\": %u,\n", (unsigned int)(type & ARGUS_VERSION_MASK));
   RadsrsIndent(2);
   fprintf(stdout, "\"cause_raw\": %u,\n", (unsigned int)cause);
   RadsrsIndent(2);
   fprintf(stdout, "\"length_words\": %u,\n", length_words);
   RadsrsIndent(2);
   fprintf(stdout, "\"length_bytes\": %lu,\n", (unsigned long)length_words * 4);
   RadsrsIndent(2);
   fputs("\"raw_base64\": ", stdout);
   if (have_raw)
      RadsrsJsonBase64(raw, raw_length);
   else
      fputs("null", stdout);
   fputc('\n', stdout);
   RadsrsIndent(1);
   fputs("},\n", stdout);

   RadsrsIndent(1);
   fputs("\"dsrs\": ", stdout);
   if (have_raw && ((type & 0xf0) != ARGUS_MAR))
      RadsrsPrintRawDsrs(raw, raw_length, 1);
   else
      fputs("[]", stdout);
   fputs(",\n", stdout);

   RadsrsIndent(1);
   fputs("\"canonical\": ", stdout);
   RadsrsPrintCanonical(argus, 1);
   fputc('\n', stdout);
   fputs("}\n", stdout);
}

#undef fprintf
#undef fputc
#undef fputs

int
ArgusRadsrsWriteRecord(FILE *out, const struct ArgusRecordStruct *record,
                       unsigned long sequence)
{
   struct RadsrsWriter writer;

   if ((out == NULL) || (record == NULL)) {
      errno = EINVAL;
      return -1;
   }
    memset(&writer, 0, sizeof(writer));
    writer.stream = out;
    if (RadsrsWriterBegin(&writer) < 0)
       return -1;
    RadsrsPrintRecord(record, sequence);
    RadsrsWriterEnd();
   return writer.failed ? -1 : 0;
}

int
ArgusRadsrsSerializeRecord(const struct ArgusRecordStruct *record,
                           unsigned long sequence, char **jsonseq,
                           size_t *jsonseq_len)
{
   struct RadsrsWriter writer;

   if ((record == NULL) || (jsonseq == NULL) || (jsonseq_len == NULL)) {
      errno = EINVAL;
      return -1;
   }
    *jsonseq = NULL;
    *jsonseq_len = 0;
    memset(&writer, 0, sizeof(writer));
    if (RadsrsWriterBegin(&writer) < 0)
       return -1;
    RadsrsPrintRecord(record, sequence);
    RadsrsWriterEnd();

   if (writer.failed || (writer.data == NULL)) {
      free(writer.data);
      return -1;
   }

   *jsonseq = writer.data;
   *jsonseq_len = writer.length;
   return 0;
}

void
ArgusRadsrsFreeSerializedRecord(char *jsonseq)
{
   free(jsonseq);
}

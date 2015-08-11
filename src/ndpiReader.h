/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2014 - Matteo Bogo <matteo.bogo@gmail.com> (JSON support)
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <pcap/pcap.h>

#ifndef _NDPI_READER_H_

#define _NDPI_READER_H_

#define MAX_PROTOCOLS 256

typedef void (*callback)(int, const uint8_t *packet);

void init();
void setDatalinkType(pcap_t *handle);
void processPacket(const struct pcap_pkthdr *header, const uint8_t *packet);
void finish();
void addProtocolHandler(callback handler);

#endif

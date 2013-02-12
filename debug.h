// dnsscrape: scrape live pcap capture for DNS requests
//
// Copyright (c) 2013 Matt Banack <matt@banack.net>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

#ifndef DNSSCRAPE_DEBUG_H
#define DNSSCRAPE_DEBUG_H

#define DEBUG_MALLOC_FREE (0)

extern int memct_rsec;
extern int memct_qsec;
extern int memct_str;

#if DEBUG_MALLOC_FREE
#define DEBUG_MF(...)   fprintf(stderr, "[MF] {#q: %d, #r:%d, #str:%d} ", memct_qsec, memct_rsec, memct_str); fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_MF(...)
#endif

void debug_enum_devs();

#endif


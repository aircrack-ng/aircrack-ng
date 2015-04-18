/*
 *  Copyright (C) 2010 Pedro Larbig <pedro.larbig@carhs.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#include <pcap.h>

// Statistics
uint32_t stats_files = 0;
uint32_t stats_dirs = 0;
uint32_t stats_caps = 0;
uint32_t stats_noncaps = 0;
uint32_t stats_packets = 0;
uint32_t stats_eapols = 0;
uint32_t stats_networks = 0;

// Global Dumpfile
pcap_t *dumphandle;
pcap_dumper_t *dumper;


struct bsslist {
  u_char *bssid;
  u_char beacon_saved;
  struct bsslist *next;
};


struct bsslist *is_in_list(struct bsslist *bsl, const u_char *bssid) {

  while (bsl != NULL) {
    if (! memcmp(bsl->bssid, bssid, 6)) return bsl;
    bsl = bsl->next;
  }
  
  return NULL;
}


struct bsslist *add_to_list(struct bsslist *bsl, const u_char *bssid) {
  struct bsslist *new, *search;
  
  new= malloc(sizeof(struct bsslist));
  new->bssid = malloc(6);
    
  memcpy(new->bssid, bssid, 6);
  new->next = NULL;
  new->beacon_saved = 0x00;

  if (bsl == NULL) {
    return new;
  } else {
    search = bsl;
    while (search->next) search = search->next;
    search->next = new;
    return bsl;
  }
}


void free_bsslist(struct bsslist *bsl) {
  if (! bsl) return;
  
  if (bsl->next) free_bsslist(bsl->next);
  
  free(bsl->bssid);
  free(bsl);
}


struct bsslist *get_eapol_bssids(pcap_t *handle) {
  struct pcap_pkthdr header;
  const u_char *pkt, *llc, *bssid, *offset = NULL;
  struct bsslist *bsl = NULL;
  int o = 0;
  
  pkt = pcap_next(handle, &header);

  if (pcap_datalink(handle) == DLT_PRISM_HEADER) {
    if (pkt[5] || pkt[6]) {
      printf("Unsupported PRISM_HEADER format!\n");
      return NULL;
    }
    if (pkt[7] == 0x40) { //prism54 format
      offset = pkt + 7;
    } else {
      offset = pkt + 4;
    }
  }
  
  while (pkt != NULL) {
    stats_packets++;
    
    if (offset) o = (*offset);
    
    if ((pkt[0+o] == 0x08) || (pkt[0+o] == 0x88)) { //Data or QoS Data
      
      if (pkt[0+o] == 0x88) { //Qos Data has 2 bytes extra in header
	llc = pkt + 26 + o;
      } else {
	llc = pkt + 24 + o;
      }
      
      if ((pkt[1+o] & 0x03) == 0x01) { //toDS
	bssid = pkt + 4 + o;
      } else {	//fromDS - I skip adhoc and wds since its unlikely to have eapol in there (?)
	bssid = pkt + 10 + o;
      }
      
      if (! memcmp(llc, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) {
	stats_eapols++;
	
	if (! is_in_list(bsl, bssid)) {
	  printf("EAPOL found for BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
	  bsl = add_to_list(bsl, bssid);
	  stats_networks++;
	}
      }
    }
    
    pkt = pcap_next(handle, &header);
  }
  
  return bsl;
}


void process_eapol_networks(pcap_t *handle, struct bsslist *bsl) {
  struct pcap_pkthdr header;
  const u_char *pkt, *llc, *bssid, *offset = 0;
  struct bsslist *known;
  int o = 0;
  
  pkt = pcap_next(handle, &header);
  
  if (pcap_datalink(handle) == DLT_PRISM_HEADER) {
    if (pkt[7] == 0x40) { //prism54 format
      offset = pkt + 7;
    } else {
      offset = pkt + 4;
    }
  }
  
  while (pkt != NULL) {
    
    if (offset) o = (*offset);
    header.len -= o;
    
    if ((pkt[0+o] == 0x08) || (pkt[0+o] == 0x88) || (pkt[0+o] == 0x80)) {

      if ((pkt[1+o] & 0x03) == 0x01) { //toDS
	bssid = pkt + 4 + o;
      } else if ((pkt[1+o] & 0x03) == 0x00) {	//beacon
	bssid = pkt + 16 + o;
      } else {	//fromDS
	bssid = pkt + 10 + o;
      }
      
      if (pkt[0+o] == 0x80) {	//beacon
	known = is_in_list(bsl, bssid);
	if (!known || known->beacon_saved) {
	  pkt = pcap_next(handle, &header);
	  continue;
	}
	
	//Saving ONE beacon per WPA network
	pcap_dump((u_char *) dumper, &header, pkt + o);
	known->beacon_saved = 0x01;
      }
      
      if (pkt[0+o] == 0x88) {
	//printf("QoS Data\n");
	llc = pkt + 26 + o;
      } else {
	llc = pkt + 24 + o;
      }
      
      if (! memcmp(llc, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8)) {
	if (is_in_list(bsl, bssid)) {
	  // Saving EAPOL
	  pcap_dump((u_char *) dumper, &header, pkt + o);
	}
      }
    }
    
    pkt = pcap_next(handle, &header);
  }
}


void process_file(const char *file) {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bsslist *eapol_networks = NULL;
  
  stats_files++;
  
  handle = pcap_open_offline(file, errbuf);
  if (! handle) {
    stats_noncaps++;
    return;
  }
  
  stats_caps++;
  
  if ((pcap_datalink(handle) != DLT_IEEE802_11) && (pcap_datalink(handle) != DLT_PRISM_HEADER)){
    //TODO: Add support for RADIOTAP!!!!
    printf("Dumpfile %s is not an IEEE 802.11 capture: %s\n", file, pcap_datalink_val_to_name(pcap_datalink(handle)));
    pcap_close(handle);
    return;
  }
  
  printf("Scanning dumpfile %s\n", file);
  eapol_networks = get_eapol_bssids(handle);
  
  pcap_close(handle);
  if (! eapol_networks) return; //No WPA networks found, skipping to next file
  
  handle = pcap_open_offline(file, errbuf);
  
  process_eapol_networks(handle, eapol_networks);
  pcap_close(handle);
  
  free_bsslist(eapol_networks);
}


void process_directory(const char *dir, time_t begin) {
  DIR *curdir;
  struct dirent *curent;
  struct stat curstat;
  char *fullname;
  
  stats_dirs++;
  
  curdir = opendir(dir);
  
  if (! curdir) {
    perror("Opening directory failed");
    return;
  }
  
  errno = 0;
  curent = readdir(curdir);
  
  while(curent) {
    if ((! strcmp("..", curent->d_name)) || (! strcmp(".", curent->d_name))) {
      curent = readdir(curdir);
      continue;
    }
    
    fullname = malloc(strlen(dir) + strlen(curent->d_name) + 2);
    memcpy(fullname, dir, strlen(dir) + 1);
    strcat(fullname, "/"); strcat(fullname, curent->d_name);
    
    if (stat(fullname, &curstat)) {
      printf("Statting %s ", fullname); perror("failed");
    } else {
      if (S_ISREG(curstat.st_mode)) {
	if (curstat.st_mtime >= begin) {
	  printf("Skipping file %s, which is newer than the crawler process (avoid loops)\n", fullname);
	} else {
	  process_file(fullname);
	}
      } else if (S_ISDIR(curstat.st_mode)) {
	process_directory(fullname, begin);
      } else {
	printf("%s is a neither a directory nor a regular file\n", fullname);
      }
    }
    
    free(fullname);
    curent = readdir(curdir);
  }
  
  if (errno) perror("Reading directory failed");
  
  closedir(curdir);
  return;
}


int main(int argc, char *argv[]) {
  time_t begin = time(NULL);	//Every file newer than when crawler started is skipped (it may be the file the crawler created!)
  
  if (argc != 3) {
    printf("Use: %s <SearchDir> <CapFileOut>\n", argv[0]);
    printf("What does it do?\n\nIt recurses the SearchDir directory\n");
    printf("Opens all files in there, searching for pcap-dumpfiles\n");
    printf("Filters out a single beacon and all EAPOL frames from the WPA networks in there\n");
    printf("And saves them to CapFileOut.\n\n");
    printf("This tool is supposed to crawl capfiles for upload to sorbo's WPA statistic server!\n");
    exit(0);
  }
  
  dumphandle = pcap_open_dead(DLT_IEEE802_11, BUFSIZ);
  dumper = pcap_dump_open(dumphandle, argv[2]);
  
  process_directory(argv[1], begin);
  
  pcap_dump_close(dumper);
  pcap_close(dumphandle);
  
  printf("DONE. Statistics:\n");
  printf("Files scanned:      %12d\n", stats_files);
  printf("Directories scanned:%12d\n", stats_dirs);
  printf("Dumpfiles found:    %12d\n", stats_caps);
  printf("Skipped files:      %12d\n", stats_noncaps);
  printf("Packets processed:  %12d\n", stats_packets);
  printf("EAPOL packets:      %12d\n", stats_eapols);
  printf("WPA Network count:  %12d\n", stats_networks);
  
  return 0;
}

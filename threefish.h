#include <stdint.h>

// Cipher context. Store any state stuff here; e.g. you might put
// round keys, counters, etc.
typedef struct {
unsigned long keyschedule[19][8];
unsigned long counter[8];
unsigned char stored_avail_cntr_bytes[64];
unsigned char avail_cntr_bytes;
} tctx;

void crypt(unsigned char *, unsigned char *, int, tctx *);
void init(const unsigned char *, const unsigned char *, tctx *);


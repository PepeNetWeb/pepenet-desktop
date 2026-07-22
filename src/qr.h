// qr.h — QR Code encoder for the Receive screen (see qr.c for scope).
#ifndef SHIB_QR_H
#define SHIB_QR_H

#define QR_MAX_SIZE 33      // version 4 = 33×33 modules
#define QR_MAX_TEXT 78      // byte capacity of version 4 at ECC level L

// Encodes text (byte mode, ECC L, smallest version 1–4 that fits) into mods:
// row-major, stride = *size, 1 = dark module. mods must hold
// QR_MAX_SIZE×QR_MAX_SIZE bytes. Returns 1, or 0 if empty / over capacity.
int qr_encode(const char *text, unsigned char *mods, int *size);

#endif

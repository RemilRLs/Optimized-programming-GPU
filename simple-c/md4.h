/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md4.c for more information.
 */

#if !defined(_MD4_H)
#define _MD4_H




/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD4_u32plus;

typedef struct {
	MD4_u32plus A, B, C, D; // Registers of the MD4
	MD4_u32plus lo, hi;
	unsigned char buffer[64];
#if !ARCH_ALLOWS_UNALIGNED
	MD4_u32plus block[16];
#endif
} MD4_CTX;

void MD4_Init(MD4_CTX *ctx);
void MD4_AllInOne(const unsigned char *data, unsigned long size, unsigned char *out, MD4_CTX *ctx);
void body(MD4_CTX *ctx, const MD4_u32plus* data, unsigned long size);

#endif

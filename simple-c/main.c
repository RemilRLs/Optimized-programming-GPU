#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>


#include "../includes/config.h"
#include "md4.h"

const uint32_t MD4_INIT_A = 0x67452301;
const uint32_t MD4_INIT_B = 0xefcdab89;
const uint32_t MD4_INIT_C = 0x98badcfe;
const uint32_t MD4_INIT_D = 0x10325476;

#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))


/*
* I go through three round (16 steps)
* 1. F function
* 2. A  : Register
* 3. B  : Register
* 4. C  : Register
* 5. D  : Register
* 6. n  : Index of the data (32 bits)
* 7. s  : Number of bits to shift
* 8. data : Data to hash
* 9. size : Size of the data
* 10. constant : Constant value (Round : 0 | Round : 1 : 0x5a827999 | Round : 2 : 0x6ed9eba1)
*
* x : To handle the padding (I think)
* a : Doing operation on the register a (everything is done inside a)
* a : Then I shift on the left then I combine with '|' and I shift on the right (beacause why NOT)
*/
#define STEP(f, a, b, c, d, n, s, data, size, constant) \
    do { \
        MD4_u32plus x = data[n]; \
        (a) += f((b), (c), (d)) + x + (constant); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    } while(0)

/**
 * Body to get hash of the data (I do the round here)
 * 
 * @param ctx : The MD4_CTX
 * @param data : The data to hash
 * @param size : The size of the data
 */
void body(MD4_CTX *ctx, const MD4_u32plus *data, unsigned long size)
{
    MD4_u32plus a, b, c, d;
    MD4_u32plus saved_a, saved_b, saved_c, saved_d;

    a = ctx->A;
    b = ctx->B;
    c = ctx->C;
    d = ctx->D;

    saved_a = a;
    saved_b = b;
    saved_c = c;
    saved_d = d;

    /* Round 1 */
    STEP(F, a, b, c, d, 0, 3, data, size, 0);
    STEP(F, d, a, b, c, 1, 7, data, size, 0);
    STEP(F, c, d, a, b, 2, 11, data, size, 0);
    STEP(F, b, c, d, a, 3, 19, data, size, 0);
    STEP(F, a, b, c, d, 4, 3, data, size, 0);
    STEP(F, d, a, b, c, 5, 7, data, size, 0);
    STEP(F, c, d, a, b, 6, 11, data, size, 0);
    STEP(F, b, c, d, a, 7, 19, data, size, 0);
    STEP(F, a, b, c, d, 8, 3, data, size, 0);
    STEP(F, d, a, b, c, 9, 7, data, size, 0);
    STEP(F, c, d, a, b, 10, 11, data, size, 0);
    STEP(F, b, c, d, a, 11, 19, data, size, 0);
    STEP(F, a, b, c, d, 12, 3, data, size, 0);
    STEP(F, d, a, b, c, 13, 7, data, size, 0);
    STEP(F, c, d, a, b, 14, 11, data, size, 0);
    STEP(F, b, c, d, a, 15, 19, data, size, 0);

    /* Round 2 */
    STEP(G, a, b, c, d, 0, 3, data, size, 0x5a827999);
    STEP(G, d, a, b, c, 4, 5, data, size, 0x5a827999);
    STEP(G, c, d, a, b, 8, 9, data, size, 0x5a827999);
    STEP(G, b, c, d, a, 12, 13, data, size, 0x5a827999);
    STEP(G, a, b, c, d, 1, 3, data, size, 0x5a827999);
    STEP(G, d, a, b, c, 5, 5, data, size, 0x5a827999);
    STEP(G, c, d, a, b, 9, 9, data, size, 0x5a827999);
    STEP(G, b, c, d, a, 13, 13, data, size, 0x5a827999);
    STEP(G, a, b, c, d, 2, 3, data, size, 0x5a827999);
    STEP(G, d, a, b, c, 6, 5, data, size, 0x5a827999);
    STEP(G, c, d, a, b, 10, 9, data, size, 0x5a827999);
    STEP(G, b, c, d, a, 14, 13, data, size, 0x5a827999);
    STEP(G, a, b, c, d, 3, 3, data, size, 0x5a827999);
    STEP(G, d, a, b, c, 7, 5, data, size, 0x5a827999);
    STEP(G, c, d, a, b, 11, 9, data, size, 0x5a827999);
    STEP(G, b, c, d, a, 15, 13, data, size, 0x5a827999);

    /* Round 3 */
    STEP(H, a, b, c, d, 0, 3, data, size, 0x6ed9eba1);
    STEP(H2, d, a, b, c, 8, 9, data, size, 0x6ed9eba1);
    STEP(H, c, d, a, b, 4, 11, data, size, 0x6ed9eba1);
    STEP(H2, b, c, d, a, 12, 15, data, size, 0x6ed9eba1);
    STEP(H, a, b, c, d, 2, 3, data, size, 0x6ed9eba1);
    STEP(H2, d, a, b, c, 10, 9, data, size, 0x6ed9eba1);
    STEP(H, c, d, a, b, 6, 11, data, size, 0x6ed9eba1);
    STEP(H2, b, c, d, a, 14, 15, data, size, 0x6ed9eba1);
    STEP(H, a, b, c, d, 1, 3, data, size, 0x6ed9eba1);
    STEP(H2, d, a, b, c, 9, 9, data, size, 0x6ed9eba1);
    STEP(H, c, d, a, b, 5, 11, data, size, 0x6ed9eba1);
    STEP(H2, b, c, d, a, 13, 15, data, size, 0x6ed9eba1);
    STEP(H, a, b, c, d, 3, 3, data, size, 0x6ed9eba1);
    STEP(H2, d, a, b, c, 11, 9, data, size, 0x6ed9eba1);
    STEP(H, c, d, a, b, 7, 11, data, size, 0x6ed9eba1);
    STEP(H2, b, c, d, a, 15, 15, data, size, 0x6ed9eba1);


    a += saved_a;
    b += saved_b;
    c += saved_c;
    d += saved_d;


    ctx->A = a;
    ctx->B = b;
    ctx->C = c;
    ctx->D = d;
}

/** 
* Init the MD4_CTX
*
* @param ctx : The MD4_CTX
*/
void MD4_Init(MD4_CTX *ctx) {
  memset(ctx->buffer, 0, 64);
  ctx->A = MD4_INIT_A;
  ctx->B = MD4_INIT_B;
  ctx->C = MD4_INIT_C;
  ctx->D = MD4_INIT_D;
  ctx->lo = 0;
  ctx->hi = 0;

  ctx->buffer[57] = 0;
  ctx->buffer[58] = 0;
  ctx->buffer[59] = 0;
}

/**
 * Method MD4_AllInOne that contain all steps for MD4 like :
 * Method Update & Method Final
 * 
 * @param data : The data to hash
 * @param size : The size of the data
 * @param out : The output of the hash
 * @param ctx : MD4 Context
*/
void MD4_AllInOne(const unsigned char *data, unsigned long size, unsigned char *out, MD4_CTX *ctx) {
    // Init Phase
    ctx->lo = size;
    ctx->hi = 0;


    memcpy(ctx->buffer, data, size);
    // I put the padding myself

    ctx->buffer[size++] = 0x80;// Padding

    // I fill with 0 after the padding

    memset(&ctx->buffer[size], 0, 64 - size - 8); // The - 8 is because last 8 bytes are for the size of the data
    uint32_t bit_len = (uint32_t)(ctx->lo << 3);

    ctx->buffer[56] = bit_len;

    // I call the body function

    body(ctx, (const MD4_u32plus *)ctx->buffer, 64); // Going to shake everything

    // I write the output (Final STEP to)
    memcpy(out, &ctx->A, 4);
    memcpy(out + 4, &ctx->B, 4);
    memcpy(out + 8, &ctx->C, 4);
    memcpy(out + 12, &ctx->D, 4);

}

/**
 * Method to get password candidature (for bruteforcing)
 * 
 * @param ptr : The pointer to the password
 * @param current_len : Length of the password
 */
int incr_candidate(char *ptr, int *current_len) {
    ssize_t pos = *current_len - 1;
    while (1) {
        if (pos < 0) { // We have done all the possibilities in my case it's between 'a' and 'z'
            if (*current_len < MAX_LEN) { // 
                ptr[*current_len] = '\0'; // We add at the end of the data '\0'
                (*current_len)++;
                return 1;
            }
            return 0;
        }
        char c = ++ptr[pos]; // a -> b -> c -> ... -> z
        if (c > 'z') { // Just in case if we go more than z we go back to a
            ptr[pos] = 'a';
            pos--; // We go to the next character on the left
        } else {
            return 1;
        }
    }
}


int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s HASH\n", argv[0]);
    return -1;
  }
  unsigned char *target = parse_hash(argv[1]);
  if (!target) {
      fprintf(stderr, "[X] - Error during the parse of the hash\n");
      return -1;
  }
    
  char *candidate = malloc(MAX_LEN + 1);

  if (!candidate) {
      fprintf(stderr, "[X] - Error during allocation\n");
      free(target);
      return -1;
  }

  memset(candidate, 'a', MIN_LEN);
  candidate[MIN_LEN] = '\0';

  MD4_CTX base_ctx;
  MD4_Init(&base_ctx);


  struct timeval tval;
  double start;
  double now;

  gettimeofday(&tval, NULL);
  start = tval.tv_sec + tval.tv_usec / 1000000.0;

  unsigned char res[16]; // Store the result of the hash
  int current_len = MIN_LEN;
  size_t tested = 0;

  do {
     
      MD4_CTX temp_ctx = base_ctx; // Copy the base context (that like my reference)

      MD4_AllInOne((unsigned char *)candidate, current_len, res, &temp_ctx);

      tested++;

      if (memcmp(res, target, 16) == 0) {
          printf("[+] - Found: %s, after %ld tries\n", candidate, tested);
          free(candidate);
          free(target);
          return 0;
      }

      if (tested % (1024 * 1024 * 32) == 0) {
          gettimeofday(&tval, NULL);
          now = tval.tv_sec + tval.tv_usec / 1000000.0;
          double speed = tested / (now - start);
          fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);
      }
  } while (incr_candidate(candidate, &current_len));

  printf("[X] - Not found after %ld tries\n", tested);
  free(candidate);
  free(target);
  return 1;
}
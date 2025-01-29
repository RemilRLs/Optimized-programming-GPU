#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#define PWD_LEN 6 // Len of the password
#define MD4_DIGEST_SIZE 4

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
* 10. constant : Constant value (Round : 0 | Round : 1 : 0x5a827999 | Round : 2 : 0x6ed9eba1)
*
* x : To handle the padding (I think)
* a : Doing operation on the register a (everything is done inside a)
* a : Then I shift on the left then I combine with '|' and I shift on the right (beacause why NOT)
*/
#define STEP(f, a, b, c, d, n, s, data, constant) \
    do { \
        uint x = data[n]; \
        (a) += f((b), (c), (d)) + x + (constant); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    } while(0)


typedef struct {
    uint A, B, C, D; // Registers
    uint lo, hi; // Length
    uint buffer[16]; 
} MD4_CTX;


/**
* Increment the password character by character
* @candidate : Start candidate (password)
* @start_pos : Start position (3 in my case)
*
* @return 0 if the password is fully incremented (zzzzzz) 1 otherwise
*/
int incr_candidate(char *candidate, int start_pos) {
    size_t pos = PWD_LEN - 1; 
    while (1)
    {
        if (pos < 3)
        {
            return 0;
        }
        char c = ++candidate[pos];
        if (c == '\'')
        {
            candidate[pos] = 'a';
            return 1;
        }
        if (c <= '&')
            return 1;
        if (c > 'z')
        {
            candidate[pos] = '!';
            pos--;
        } else {
            return 1;
        }
    }
    return 0; 
}

/**
* Kernel (GPU) function to crack the MD4 hash that user gave me
* @target_hash : The hash to crack
* @found_password : The password found link to the target hash
*/
__kernel void md4_crack(__global const unsigned char *target_hash,
                        __global unsigned char *found_password) {

    uint id = get_global_id(0); // Thread id in my case there (26 * 26 * 32 threads = 21632)
    
    char password[PWD_LEN + 1];
    uint temp_id = id;


    // I build the start password : aaa!!! (with 6 for PWD_LEN)
    password[0] = (temp_id % 26) + 'a';
    temp_id /= 26;
    password[1] = (temp_id % 26) + 'a';
    temp_id /= 26;
    password[2] = temp_id < 6 ? temp_id + '!' : temp_id  + 'a' - 6;
    for(int i=3; i<PWD_LEN; i++) password[i] = '!';

    password[PWD_LEN] = 0; // Null byte at the end.

    do {

        MD4_CTX ctx;

        // Init Registers
        ctx.A = 0x67452301;
        ctx.B = 0xefcdab89;
        ctx.C = 0x98badcfe;
        ctx.D = 0x10325476;

        ctx.lo = PWD_LEN * 8;
        ctx.hi = 0;

        // Init buffer
        for(int i = 0; i < 16; i++) {
            ctx.buffer[i] = 0;
        }
        // I add my password inside the buffer to be hashed
        for (int i = 0; i < PWD_LEN; i++) {
            ctx.buffer[i / 4] |= (uint)password[i] << ((i % 4) * 8);
        }

        // Padding (Little-endian that why I do that)
        ctx.buffer[PWD_LEN / 4] |= 0x80 << ((PWD_LEN % 4) * 8);

        // Length
        ctx.buffer[14] = ctx.lo;
        ctx.buffer[15] = ctx.hi;

        uint a = ctx.A, b = ctx.B, c = ctx.C, d = ctx.D;
        uint saved_a = a, saved_b = b, saved_c = c, saved_d = d;

        // Round 1
        STEP(F, a, b, c, d, 0, 3, ctx.buffer, 0);
        STEP(F, d, a, b, c, 1, 7, ctx.buffer, 0);
        STEP(F, c, d, a, b, 2, 11, ctx.buffer, 0);
        STEP(F, b, c, d, a, 3, 19, ctx.buffer, 0);
        STEP(F, a, b, c, d, 4, 3, ctx.buffer, 0);
        STEP(F, d, a, b, c, 5, 7, ctx.buffer, 0);
        STEP(F, c, d, a, b, 6, 11, ctx.buffer, 0);
        STEP(F, b, c, d, a, 7, 19, ctx.buffer, 0);
        STEP(F, a, b, c, d, 8, 3, ctx.buffer, 0);
        STEP(F, d, a, b, c, 9, 7, ctx.buffer, 0);
        STEP(F, c, d, a, b, 10, 11, ctx.buffer, 0);
        STEP(F, b, c, d, a, 11, 19, ctx.buffer, 0);
        STEP(F, a, b, c, d, 12, 3, ctx.buffer, 0);
        STEP(F, d, a, b, c, 13, 7, ctx.buffer, 0);
        STEP(F, c, d, a, b, 14, 11, ctx.buffer, 0);
        STEP(F, b, c, d, a, 15, 19, ctx.buffer, 0);

        // Round 2
        STEP(G, a, b, c, d, 0, 3, ctx.buffer, 0x5a827999);
        STEP(G, d, a, b, c, 4, 5, ctx.buffer, 0x5a827999);
        STEP(G, c, d, a, b, 8, 9, ctx.buffer, 0x5a827999);
        STEP(G, b, c, d, a, 12, 13, ctx.buffer, 0x5a827999);
        STEP(G, a, b, c, d, 1, 3, ctx.buffer, 0x5a827999);
        STEP(G, d, a, b, c, 5, 5, ctx.buffer, 0x5a827999);
        STEP(G, c, d, a, b, 9, 9, ctx.buffer, 0x5a827999);
        STEP(G, b, c, d, a, 13, 13, ctx.buffer, 0x5a827999);
        STEP(G, a, b, c, d, 2, 3, ctx.buffer, 0x5a827999);
        STEP(G, d, a, b, c, 6, 5, ctx.buffer, 0x5a827999);
        STEP(G, c, d, a, b, 10, 9, ctx.buffer, 0x5a827999);
        STEP(G, b, c, d, a, 14, 13, ctx.buffer, 0x5a827999);
        STEP(G, a, b, c, d, 3, 3, ctx.buffer, 0x5a827999);
        STEP(G, d, a, b, c, 7, 5, ctx.buffer, 0x5a827999);
        STEP(G, c, d, a, b, 11, 9, ctx.buffer, 0x5a827999);
        STEP(G, b, c, d, a, 15, 13, ctx.buffer, 0x5a827999);

        // Round 3
        STEP(H, a, b, c, d, 0, 3, ctx.buffer, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 8, 9, ctx.buffer, 0x6ed9eba1);
        STEP(H, c, d, a, b, 4, 11, ctx.buffer, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 12, 15, ctx.buffer, 0x6ed9eba1);
        STEP(H, a, b, c, d, 2, 3, ctx.buffer, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 10, 9, ctx.buffer, 0x6ed9eba1);
        STEP(H, c, d, a, b, 6, 11, ctx.buffer, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 14, 15, ctx.buffer, 0x6ed9eba1);
        STEP(H, a, b, c, d, 1, 3, ctx.buffer, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 9, 9, ctx.buffer, 0x6ed9eba1);
        STEP(H, c, d, a, b, 5, 11, ctx.buffer, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 13, 15, ctx.buffer, 0x6ed9eba1);
        STEP(H, a, b, c, d, 3, 3, ctx.buffer, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 11, 9, ctx.buffer, 0x6ed9eba1);
        STEP(H, c, d, a, b, 7, 11, ctx.buffer, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 15, 15, ctx.buffer, 0x6ed9eba1);

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ctx.A = a;
        ctx.B = b;
        ctx.C = c;
        ctx.D = d;
        
        uint hash[4] = {a, b, c, d};
        uint output[MD4_DIGEST_SIZE * 8];


        unsigned char hash_bytes[16];

        // I convert my hash to print it and compare it

        hash_bytes[0] = (unsigned char)a;
        hash_bytes[1] = (unsigned char)(a >> 8);
        hash_bytes[2] = (unsigned char)(a >> 16);
        hash_bytes[3] = (unsigned char)(a >> 24);
        hash_bytes[4] = (unsigned char)b;
        hash_bytes[5] = (unsigned char)(b >> 8);
        hash_bytes[6] = (unsigned char)(b >> 16);
        hash_bytes[7] = (unsigned char)(b >> 24);
        hash_bytes[8] = (unsigned char)c;
        hash_bytes[9] = (unsigned char)(c >> 8);
        hash_bytes[10] = (unsigned char)(c >> 16);
        hash_bytes[11] = (unsigned char)(c >> 24);
        hash_bytes[12] = (unsigned char)d;
        hash_bytes[13] = (unsigned char)(d >> 8);
        hash_bytes[14] = (unsigned char)(d >> 16);
        hash_bytes[15] = (unsigned char)(d >> 24);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (hash_bytes[i] != target_hash[i]) {
                match = false;
                break;
            }
        }

        if (match) {
            printf("\n--------------------------------------------------");
            printf("\n[+] - Match: %d\n", match);

            for (int i = 0; i < PWD_LEN; i++) {
                found_password[i] = password[i];
            }
            found_password[PWD_LEN] = '\0';

            printf("[+] - Password : ");
            for(int i = 0; i < PWD_LEN; i++) {
                printf("%c", password[i]);
            }

            printf("\n[+] - Computed Hash: ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", hash_bytes[i]);
            }
            
            printf("\n[>] - Target Hash:   ");
            for (int i = 0; i < 16; i++) {
                printf("%02x", target_hash[i]);
            }
            printf("\n--------------------------------------------------");

            printf("\n\n");
        }
    } while(incr_candidate(password, 3));
    


}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <openssl/aes.h> 
#include <openssl/cmac.h>

#include "utils.h"

u32 rand32(u32 rand[4])
{
    u32 t = rand[0];
    t ^= (t << 11);
    t ^= (t >> 8);
    t ^= rand[3];
    t ^= (rand[3] >> 19);
    
    rand[0] = rand[1];
    rand[1] = rand[2];
    rand[2] = rand[3];
    rand[3] = t;
    return t;
}

u32 lookup_table[64] = {0};

void generate_randkey(u32 rand[4], u8 key[16])
{
    u32* key32 = (u32*)key;
    memset(key, 0, 16);
    
    // outer loop is for each u32 of the key, inner is for each u8
    for(u32 i = 0; i < 4; i++)
    {
        for(u32 j = 0; j < 4; j++)
        {
            u32 state = key32[i];
            // get a lookup value from a random index within bounds
            u32 lookup = lookup_table[rand32(rand) >> 26];
            // generate 2 random bits in bits 3 and 4
            u32 t = (rand32(rand) >> 27) & 0x18;
            
            // shift lookup by t value, use this as the bottom u8 of the state
            t = lookup >> t;
            state |= (t & 0xFF);
            
            // shift to free up the bottom u8, unless we just set it
            if(j != 3)
                state = state << 8;
            
            key32[i] = state;
        }
    }
}

// all little-endian, be sure to use getle32/etc to be safe
typedef struct {
    u32 product_version;
    u32 develop_version;
    u32 crc32;
    u32 pad;
} save_header;

typedef struct {
    u8 iv[16];
    u32 rand[4]; // random ctx used to generate keys
    u8 aes_cmac[16];
} save_cryptinfo;

void do_body_cmac(u8 *save_body, uint64_t body_size, u8 key[16], u8 cmac_out[16])
{
    size_t cmac_out_len;
    CMAC_CTX *cmac = CMAC_CTX_new();
    CMAC_Init(cmac, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(cmac, save_body, body_size);
    CMAC_Final(cmac, cmac_out, &cmac_out_len);
    CMAC_CTX_free(cmac);
}

void decrypt_save(u8* save_buf, u64 fsize)
{
    save_header *save_head = (save_header*)save_buf;
    save_cryptinfo* cryptinfo = (save_cryptinfo*)(save_buf + fsize - sizeof(save_cryptinfo));
    u8* body = save_buf + sizeof(save_header);
    uint64_t body_size = fsize - sizeof(save_header) - sizeof(save_cryptinfo);
    
    // Store iv
    u32 iv[4];
    memcpy(iv, cryptinfo->iv, sizeof(iv));
    
    // pull in the rand ctx and generate keys
    u32 rand_ctx[4];
    for(int i = 0; i < 4; i++)
        rand_ctx[i] = getle32(&cryptinfo->rand[i]);
    
    u8 enc_key[16];
    u8 auth_key[16];
    generate_randkey(rand_ctx, enc_key);
    generate_randkey(rand_ctx, auth_key);
    
    AES_KEY aes;
    AES_set_decrypt_key(enc_key, 128, &aes);
    AES_cbc_encrypt(body, body, body_size, &aes, (u8*)iv, AES_DECRYPT);

    printf("Save decrypted, verifying AES-CMAC...\n");
    u8 cmac_out[16];
    do_body_cmac(body, body_size, auth_key, cmac_out);
    
    if(memcmp(cmac_out, &cryptinfo->aes_cmac, sizeof(cmac_out)))
        printf("CMAC check failed!\n");
    else
        printf("CMAC check passed!\n");
    
    printf("Checking CRC32...\n");
    u32 crc = crc32(body, body_size);
    if(memcmp(&crc, &save_head->crc32, sizeof(crc)))
        printf("CRC check failed!\n");
    else
        printf("CRC check passed!\n");
    
    printf("Writing out...\n");
}

void encrypt_save(u8* save_buf, u64 fsize)
{
    save_header *save_head = (save_header*)save_buf;
    save_cryptinfo* cryptinfo = (save_cryptinfo*)(save_buf + fsize - sizeof(save_cryptinfo));
    u8* body = save_buf + sizeof(save_header);
    uint64_t body_size = fsize - sizeof(save_header) - sizeof(save_cryptinfo);
    
    // fix up the CRC32 over the decrypted body
    printf("Fixing up CRC32...\n");
    putle32(&save_head->crc32, crc32(body, body_size));
    
    // generate random IV and seed, and add them to the save
    printf("Generating security data...\n");
    srand(time(NULL));
    u32 rand_ctx[4];
    u32 iv[4];
    memcpy(iv, cryptinfo->iv, sizeof(iv));
    memcpy(rand_ctx, cryptinfo->rand, sizeof(rand_ctx));
    
    // generate keys
    u8 enc_key[16];
    u8 auth_key[16];
    generate_randkey(rand_ctx, enc_key);
    generate_randkey(rand_ctx, auth_key);
    
    printf("Generating save body CMAC...\n");
    // calculate AES-CMAC of decrypted data and write it to the save
    do_body_cmac(body, body_size, auth_key, (u8*)&cryptinfo->aes_cmac);
    
    // encrypt the body of the save
    printf("Encrypting save body...\n");
    AES_KEY aes;
    AES_set_encrypt_key(enc_key, 128, &aes);
    AES_cbc_encrypt(body, body, body_size, &aes, (u8*)iv, AES_ENCRYPT);
    
    printf("Writing...\n");
}

typedef enum {encrypt, decrypt} prog_mode;

int main(int argc, char* argv[])
{
    setbuf(stdout, NULL);
    printf("Super Mario Maker 2 save crypt tool v1.0\n"
        "By WulfyStylez/SALT 2k19\n\n");
    
    if(argc != 5)
    {
        printf("Usage: %s [-e|-d] [crypt_lut.bin] [save] [save_out]\n"
               "-e: encrypt a decrypted save\n"
               "-d: decrypt an encrypted save\n", argv[0]);
        return -1;
    }
    
    // check mode
    prog_mode mode;
    if(!strcmp(argv[1], "-e"))
        mode = encrypt;
    else if(!strcmp(argv[1], "-d"))
        mode = decrypt;
    else
    {
        printf("Invalid mode %s !\n", argv[1]);
        return -1;
    }

    FILE* f_lut = fopen(argv[2], "rb");
    if(f_lut == NULL)
    {
        printf("Failed to open file %s for reading!\n", argv[2]);
        return -1;
    }
    
    size_t lut_read = fread(&lookup_table, 1, 0x100, f_lut);
    if (lut_read != 0x100)
    {
        printf("Lookup table too small! Got 0x%zx bytes instead of 0x100\n", lut_read);
        return -1;
    }
    fclose(f_lut);

    FILE* f_in = fopen(argv[3], "rb");
    if(f_in == NULL)
    {
        printf("Failed to open file %s for reading!\n", argv[3]);
        return -1;
    }
    
    size_t fsize = get_fsize(f_in);
    
    // always malloc the larger size so we can safely append to v0 saves
    u8* save_buf = malloc(fsize + 0x100);
    if(save_buf == NULL)
    {
        printf("Failed to allocate %d bytes for reading game save!\n", fsize + 0x100);
        fclose(f_in);
        return -1;
    }
    
    size_t read_size = fread(save_buf, 1, fsize, f_in);
    fclose(f_in);
    if(read_size != fsize)
    {
        printf("Failed to read save file!\n");
        return -1;
    }
    
    // 60,000,000 years of C error checking later, sanity-check save and mode
    u32 version = getle32(&save_buf[0]);
    if(!version || version > 1)
    {
        printf("Unrecognized save version %d!\n", version);
        free(save_buf);
        return -1;
    }
    
    if(mode == decrypt)
        decrypt_save(save_buf, fsize);
    else if(mode == encrypt)
        encrypt_save(save_buf, fsize);
    
    FILE* f_out = fopen(argv[4], "wb");
    if(f_out == NULL)
    {
        printf("Failed to open file %s for writing!\n", argv[4]);
        free(save_buf);
        return -1;
    }
    
    size_t size_to_write = fsize;
    size_t size_written = fwrite(save_buf, 1, size_to_write, f_out);
    fclose(f_out);
    free(save_buf);
    if(size_written != size_to_write)
    {
        printf("Failed to write to output file!\n");
        return -1;
    }
    
    printf("Done!\n");
}

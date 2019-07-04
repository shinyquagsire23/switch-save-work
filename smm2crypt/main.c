#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <openssl/aes.h> 
#include <openssl/cmac.h>

#include "utils.h"
#include "keys.h"

u32 forced_lookup_table[64] = { 0 };

// all little-endian, be sure to use getle32/etc to be safe
typedef struct {
	u32 product_version;
	u32 develop_version;
	u32 crc32;
	u32 magic;
} save_header;

typedef struct {
	u8 iv[16];
	u32 rand[4]; // random ctx used to generate keys
	u8 aes_cmac[16];
} save_cryptinfo;

struct mm_file_type
{
	char* name;
	char* fileName;
	size_t fileSize;
	u32 develop_version;
	u32 magic;
	u32* key_table;
};

struct mm_file_type file_types[] = {
	{ "save", "save.dat", 0xC000, 0x0B, 0x00, save_key_table },
	{ "quest", "quest.dat", 0xC000, 0x01, 0x00, quest_key_table },
	{ "later", "later.dat", 0xC000, 0x0A, 0x00, later_key_table },
	{ "replay", ".dat", 0x68000, 0x00, 0x00, replay_key_table },
	{ "network", "network.dat", 0x48000, 0x08, 0x00, network_key_table },
	{ "thumb", ".btl", 0x1C000, 0x00, 0x00, thumb_key_table },
	{ "thumb", ".jpg", 0x1C000, 0x00, 0x00, thumb_key_table },
	{ "course", ".bcd", 0x5C000, 0x10, 0x4C444353, course_key_table }
};

char ends_with(const char* a, const char* b)
{
	if (!a || !b)
	{
		return 0;
	}

	int lenA = strlen(a);
	int lenB = strlen(b);

	if (lenB > lenA)
	{
		return 0;
	}

	return strcmp(a + lenA - lenB, b) == 0;
}

/*struct mm_file_type* get_file_type(const char* fileName, size_t size)
{
	for (int i = 0; i < sizeof(file_types) / sizeof(struct mm_file_type); i++)
	{
		if (file_types[i].fileSize == size && ends_with(fileName, file_types[i].fileName))
		{
			return &file_types[i];
		}
	}
	return NULL;
}*/

bool is_empty(const u8* ptr, size_t size)
{
	if (!ptr)
	{
		return true;
	}

	for (size_t i = 0; i < size; i++)
	{
		if (ptr[i])
		{
			return false;
		}
	}
	return true;
}

u32* get_lookup_table(const char* fileName, size_t size, save_header* header, bool is_encrypting, int* offset)
{
	if (!is_empty(forced_lookup_table, sizeof(forced_lookup_table)))
	{
		printf("using supplied lookup table.\n");
		return forced_lookup_table;
	}

	if (is_encrypting)
	{
		size += 0x30;
	}

	for (int i = 0; i < sizeof(file_types) / sizeof(struct mm_file_type); i++)
	{
		if (file_types[i].fileSize == (size + (file_types[i].develop_version && is_encrypting ? 0x10 : 0)) && ends_with(fileName, file_types[i].fileName))
		{
			if (is_encrypting && file_types[i].develop_version)
			{
				header->product_version = 1;
				header->develop_version = file_types[i].develop_version;
				header->crc32 = 0;
				header->magic = file_types[i].magic;
			}

			if (file_types[i].develop_version && offset)
			{
				*offset = 0x10;
			}

			if (!is_encrypting && file_types[i].develop_version)
			{
				if (header->product_version != 1)
				{
					printf("Unrecognized save version %d!\n", header->product_version);
				}

				if (header->develop_version != file_types[i].develop_version)
				{
					printf("Unrecognized develop version %d, expected %d!\n", header->develop_version, file_types[i].develop_version);
				}
			}

			printf("using %s lookup table.\n", file_types[i].name);
			return file_types[i].key_table;
		}
	}

	if (!is_encrypting && header && header->product_version == 1)
	{
		for (int i = 0; i < sizeof(file_types) / sizeof(struct mm_file_type); i++)
		{
			if (file_types[i].develop_version && file_types[i].develop_version == header->develop_version)
			{
				printf("using %s lookup table.\n", file_types[i].name);
				return file_types[i].key_table;
			}
		}
	}

	printf("fatal error: unable to get LUT!\n");
	return forced_lookup_table;
}

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

void generate_randkey(u32 rand[4], u8 key[16], u32* lookup_table)
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

void do_body_cmac(u8 *save_body, uint64_t body_size, u8 key[16], u8 cmac_out[16])
{
    size_t cmac_out_len;
    CMAC_CTX *cmac = CMAC_CTX_new();
    CMAC_Init(cmac, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(cmac, save_body, body_size);
    CMAC_Final(cmac, cmac_out, &cmac_out_len);
    CMAC_CTX_free(cmac);
}

void decrypt_save(u8* save_buf, u64 fsize, u32* lookup_table, int has_header)
{
    save_cryptinfo* cryptinfo = (save_cryptinfo*)(save_buf + fsize - sizeof(save_cryptinfo));
    u8* body = save_buf + (has_header ? sizeof(save_header) : 0);
    uint64_t body_size = fsize - (has_header ? sizeof(save_header) : 0) - sizeof(save_cryptinfo);
    
    // Store iv
    u32 iv[4];
    memcpy(iv, cryptinfo->iv, sizeof(iv));
    
    // pull in the rand ctx and generate keys
    u32 rand_ctx[4];
    for(int i = 0; i < 4; i++)
        rand_ctx[i] = getle32(&cryptinfo->rand[i]);
    
    u8 enc_key[16];
    u8 auth_key[16];
    generate_randkey(rand_ctx, enc_key, lookup_table);
    generate_randkey(rand_ctx, auth_key, lookup_table);
    
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
    
	if (has_header)
	{
		save_header *save_head = (save_header*)save_buf;

		printf("Checking CRC32...\n");
		u32 crc = crc32(body, body_size);
		if (memcmp(&crc, &save_head->crc32, sizeof(crc)))
			printf("CRC check failed!\n");
		else
			printf("CRC check passed!\n");
	}
    
    printf("Writing out...\n");
}

void encrypt_save(u8* save_buf, u64 fsize, u32* lookup_table, int has_header)
{
    save_cryptinfo* cryptinfo = (save_cryptinfo*)(save_buf + fsize - sizeof(save_cryptinfo));
    u8* body = save_buf + (has_header ? sizeof(save_header) : 0);
    uint64_t body_size = fsize - (has_header ? sizeof(save_header) : 0) - sizeof(save_cryptinfo);
    
	if (has_header)
	{
		save_header *save_head = (save_header*)save_buf;
		// fix up the CRC32 over the decrypted body
		printf("Fixing up CRC32...\n");
		putle32(&save_head->crc32, crc32(body, body_size));
	}
    
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
    generate_randkey(rand_ctx, enc_key, lookup_table);
    generate_randkey(rand_ctx, auth_key, lookup_table);
    
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

int print_usage(int argc, char* argv[])
{
	printf("Usage: %s [-e|-d] [crypt_lut.bin?] [save] [save_out]\n"
		"-e: encrypt a decrypted save\n"
		"-d: decrypt an encrypted save\n", argv[0]);
	return -1;
}

int main(int argc, char* argv[])
{
    setbuf(stdout, NULL);
    printf("Super Mario Maker 2 save crypt tool v1.0\n"
        "By WulfyStylez/SALT 2k19\n\n");
    
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

	const char* in_file_name = NULL;// "course_data_120.bcd";
	const char* out_file_name = NULL;// "course_data_120.bcd.dec";
	const char* lut_file_name = NULL;

	if (argc == 5)
	{
		lut_file_name = argv[2];
		in_file_name = argv[3];
		out_file_name = argv[4];
	}
	else if (argc == 4)
	{
		in_file_name = argv[2];
		out_file_name = argv[3];
	}
	else
	{
		return print_usage(argc, argv);
	}

	if (lut_file_name)
	{
		FILE* f_lut = fopen(lut_file_name, "rb");
		if (f_lut == NULL)
		{
			printf("Failed to open file %s for reading!\n", lut_file_name);
			return -1;
		}

		size_t lut_read = fread(&forced_lookup_table, 1, 0x100, f_lut);
		if (lut_read != 0x100)
		{
			printf("Lookup table too small! Got 0x%zx bytes instead of 0x100\n", lut_read);
			return -1;
		}
		fclose(f_lut);
	}

    FILE* f_in = fopen(in_file_name, "rb");
    if(f_in == NULL)
    {
        printf("Failed to open file %s for reading!\n", in_file_name);
        return -1;
    }
    
    size_t fsize = get_fsize(f_in);
    
    // always malloc the larger size so we can safely append to v0 saves
    u8* save_buf = malloc(fsize + 0x100 + 0x40);
    if(save_buf == NULL)
    {
        printf("Failed to allocate %d bytes for reading game save!\n", fsize + 0x100);
        fclose(f_in);
        return -1;
    }
    
    size_t read_size = fread(save_buf + (mode == encrypt ? 0x10 : 0x00), 1, fsize, f_in);
    fclose(f_in);
    if(read_size != fsize)
    {
        printf("Failed to read save file!\n");
        return -1;
    }
    
    // 60,000,000 years of C error checking later, sanity-check save and mode
    
	int code = 0;
	int offset = 0;

	if (mode == decrypt)
	{
		u32* lut = get_lookup_table(in_file_name, fsize, (save_header*)save_buf, false, &offset);

		decrypt_save(save_buf, fsize, lut, offset);
		if (!file_put_contents(out_file_name, save_buf + offset, fsize - 0x30 - offset))
		{
			code = -1;
		}
	}
	else if (mode == encrypt)
	{
		save_header* header = (save_header*)save_buf;

		u32* lut = get_lookup_table(in_file_name, fsize, (save_header*)save_buf, true, &offset);

		encrypt_save(save_buf + (offset ? 0 : 0x10), fsize + 0x30 + offset, lut, offset);
		if (!file_put_contents(out_file_name, save_buf + (offset ? 0 : 0x10), fsize + 0x30 + offset))
		{
			code = -1;
		}
	}

	free(save_buf);    
    printf("Done!\n");
}

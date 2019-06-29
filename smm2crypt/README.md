# smm2crypt: Super Mario Maker 2 save crypto tool.
This tool encrypts and decrypts saves from Super Mario Maker 2, based on splatcrypt. It's provided uncompiled, currently. Tested and working on \*nix, needs libssl-dev.


Usage: smm2crypt [-e|-d] lut.bin save save_out

-d will take an encrypted save and decrypt it. All headers are preserved with the body decrypted.

-e will take a decrypted save and encrypt+authenticate it for use. The save's CRC32 will also be corrected. IVs and random data are not changed.


Keydata (lut.bin) can be acquired from a Super Mario Maker executable. Each LUT is 0x100 bytes large and there are seven total in SMM2 with the following SHA256 hashes:

b871b210a0a9759b84650e33de3f203b63d2b3ef069a3a6acc41c162b3937434  lut_bcd.bin
718fba48870752ee9703c7a5938c0ac3748a6922593f584158b13a398d21522c  lut_unk1.bin
0382e07f0ba4817e429abd51517d35d4407cd723bda7bcc4eadbd6deb802ddda  lut_unk2.bin
cbc42b89e203cbb615b98b2b3259dcd1f344e72d493a869bbeec3e741fd3275b  lut_unk3.bin
a2699d42e4503240b2f0533807c304a7f613f33e8dbc4300d00cc1a584971188  lut_unk4.bin
a1b3a6012102e1e23f2f2e797f7f3d2cd3fde333fbd2bc4f570ed6093826a0e7  lut_unk5.bin
32f0e2f1be2bc55fe729877a4d0018b48031ff3184066e40a0fa69a42585f8e9  lut_unk6.bin


<?php
bool get_shared = dh2.Agree(shared_secret, privKey, ephPrivKey, g_pubKey, g_ephKey);
//converting from bytes to string
string str_shared_secret((const char*)shared_secret.data(), 64);

//about options Google manual talking about:
//CheckMode, OldCofactorMode, SingleHashMode and CofactorMode are 0 google says
//OldCofactorMode - just the same as CofactorMode (0 for us)
//SingleHashMode - if somehow true(for us it is false) - then we would send ephemeral||secret to hkdf (not only secret) (0 for us)
//CheckMode - throw error while decrypting if R(P[r] = subgr generator over random from 1..q-1)[q(prime = subgroup order)] != 0 . also 0 for us

//retrieving shared key using "Key derivation function: HKDFwithSHA256":
//info always the same, as in manual
CryptoPP::byte info[] = {'G','o','o','g','l','e'};
size_t info_len = sizeof(info)/sizeof(*info);
//empty (32 empty bytes), as said in docs
CryptoPP::byte salt[32] = {0};
size_t salt_len = sizeof(salt) / sizeof(*salt);
//secret - what we have found from ECDH
CryptoPP::byte *secret = (CryptoPP::byte*) str_shared_secret.data();
size_t secret_len = str_shared_secret.size();
//to store result
//CryptoPP::byte derived[CryptoPP::SHA256::DIGESTSIZE];
CryptoPP::SecByteBlock derived(32);
size_t derived_len = 32;
//derivation function
CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
//deriving, result in 'dervied'
hkdf.DeriveKey(derived, derived_len, secret, secret_len, salt, salt_len, info, info_len);

//splitting to two 128-bit length: symmetricEncryptionKey and macKey
CryptoPP::byte symmetricEncryptionKey[16];
CryptoPP::byte macKey[16];
memcpy(symmetricEncryptionKey, derived, 16);
memcpy(macKey, derived + 16, 16);

//checking accepted tag with MAC with HMAC SHA256
//TODO

//decrypting encryptedMessage with AES128 CTR zero IV, no padding, using symmetricEncryption key
//zero iv
CryptoPP::byte iv[16] = {0};
string decryptedtext;
CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption d;
d.SetKeyWithIV(&(symmetricEncryptionKey[0]), 16, iv, 16);
CryptoPP::StringSource(reinterpret_cast<const unsigned char*>(&(encrypted_message[0])), encrypted_message.size(), true,
	new CryptoPP::StreamTransformationFilter(d,
		new CryptoPP::StringSink(decryptedtext)
	)
);

cout << decryptedtext << std::endl;
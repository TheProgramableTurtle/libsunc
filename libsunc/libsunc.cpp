#include "libsunc.h"
#include <stdio.h>

void libsunc_init() {
	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	OPENSSL_init_ssl(0, NULL);
	return;
}

void libsunc_uninit() {
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	// need remove error state implementation
	ERR_free_strings();
	return;
}

int libsunc_auto_hash(unsigned char *string, unsigned char *hash) {
	EVP_CIPHER_CTX* ctx;
	int len;
	int text_len = strlen((char*)string);
	int ciphertext_len;
	unsigned char ciphertext[128];
	unsigned char key[256];
	unsigned char iv[128];

	memcpy(key, string, sizeof(key));
	memcpy(iv, string, sizeof(iv));

	ctx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &len, string, text_len);
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	hash = ciphertext;

	return 0;
}

int libsunc_auto_unhash(unsigned char* hash, unsigned char* key, unsigned char *string) {
	EVP_CIPHER_CTX* ctx;
	int len;
	int text_len = strlen((char*)hash);
	int ciphertext_len;
	int plaintext_len;
	unsigned char plaintext[128];
	unsigned char iv[128];

	memcpy(iv, key, sizeof(iv));

	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &len, hash, text_len);
	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	plaintext_len += len;

	string = plaintext;

	return 0;
}

int libsunc_read_pub_key(char *filepath, EVP_PKEY *key) {
	FILE *pub_key = fopen(filepath, "r");
	key = PEM_read_PUBKEY(pub_key, NULL, NULL, NULL);
	fclose(pub_key);

	return 0;
}

int libsunc_gen_uuid(char* buff) {
	union {
		struct {
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t clk_seq_hi_res;
			uint8_t clk_seq_low;
			uint8_t node[6];
		};
		uint8_t __rnd[16];
	} uuid;

	int ret = RAND_bytes(uuid.__rnd, sizeof(uuid));

	uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	snprintf(buff, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		uuid.clk_seq_hi_res, uuid.clk_seq_low,
		uuid.node[0], uuid.node[1], uuid.node[2],
		uuid.node[3], uuid.node[4], uuid.node[5]);
	return ret;
}


int libsunc_gen_id_uuid(unsigned char *uuid) {
	char *username;
	unsigned char *hash;
	strcpy(username, getenv("USERNAME"));

	unsigned char *plaintext;
	memcpy(plaintext, username, strlen(username));

	libsunc_auto_hash(plaintext, hash);

	memcpy(uuid, hash, sizeof(char[128]));
	
	return 0; // needs implementation
}

int libsunc_gen_sess_uuid(char *uuid) {
	return libsunc_gen_uuid(uuid);
}

int libsunc_gen_priv_key(EVP_PKEY* key) {
	/*
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)
	*/
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();
	EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(kctx);

	EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
	EVP_PKEY_keygen(kctx, &pkey);
	
	key = pkey;
	EVP_PKEY_CTX_free(kctx);

	return 0;
}

int libsunc_gen_pub_key(FILE *fp, EVP_PKEY *key) {
	/*
	BIO *tempBIO;
	
	PEM_write_bio_PUBKEY(tempBIO, priv_key);
	pub_key = PEM_read_bio_PUBKEY(tempBIO, NULL, NULL, NULL);
	*/

	PEM_write_PUBKEY(fp, key);
	
	return 0;
}

int libsunc_get_sess_id_folder_c(char *path) {
	unsigned char *uuid;
	libsunc_gen_id_uuid(uuid);

	char *buff;
	strcat(buff, "S:\\");
	strcat(buff, (char*)uuid);
	strcat(buff, "\\");

	path = buff;

	return 0;
}

int libsunc_get_sess_id_folder_win(LPCWSTR* path) {
	unsigned char *uuid;
	char *uuid_win;

	libsunc_gen_id_uuid(uuid);
	strcpy(uuid_win, (char*)uuid);

	LPCWSTR buff = L"S:\\%s\\", uuid_win;

	*path = buff;

	return 0;

}

int libsunc_get_sess_folder_c(char* path, unsigned char* uuid) {
	char* buff;
	strcat(buff, "S:\\sunc-sess");
	strcat(buff, (char*)uuid);
	strcat(buff, "\\");

	path = buff;

	return 0;
}

int libsunc_get_sess_folder_win(LPCWSTR* path, unsigned char* uuid) {
	char* uuid_win;
	strcpy(uuid_win, (char*)uuid);

	LPCWSTR buff = L"S:\\sunc-sess%s\\", uuid_win;

	*path = buff;

	return 0;

}

int libsunc_get_sess_id_file_path(char *path) {
	char *dir;
	unsigned char* uuid;
	char *uuid_win;

	libsunc_get_sess_id_folder_c(dir);
	libsunc_gen_id_uuid(uuid);
	strcpy(uuid_win, (char*)uuid);

	char *buff;

	strcpy(buff, dir);
	strcpy(buff, "sunc-id");
	strcpy(buff, uuid_win);
	
	return 0;
}

int libsunc_get_sess_msg_file_path(char* path, unsigned char *uuid) {
	char *dir;
	char *uuid_win;

	libsunc_get_sess_folder_c(dir, uuid);
	strcpy(uuid_win, (char*)uuid);

	char *buff;

	strcpy(buff, dir);
	strcpy(buff, "sunc-sess");
	strcpy(buff, uuid_win);

	return 0;
}

int libsunc_get_pub_key_file_path(char* path, unsigned char *uuid) {
	char* dir;
	char* uuid_win;

	libsunc_get_sess_folder_c(dir, uuid);
	strcpy(uuid_win, (char*)uuid);

	char* buff;

	strcpy(buff, dir);
	strcpy(buff, "pub");
	strcpy(buff, uuid_win);

	return 0;
}

int libsunc_create_sess_id_folder() {
	/*
	unsigned char *uuid; 
	libsunc_gen_id_uuid(uuid);
	LPCWSTR lpPathName = L"S:\\%s", uuid;
	*/
	LPCWSTR *lpPathName;
	libsunc_get_sess_id_folder_win(lpPathName);

	CreateDirectory(*lpPathName, NULL);
	SetFileAttributes(*lpPathName, FILE_ATTRIBUTE_HIDDEN);
	
	return 0;
}

int libsunc_create_sess_folder(unsigned char* uuid) {
	LPCWSTR *lpPathName;
	libsunc_get_sess_folder_win(lpPathName, uuid);

	CreateDirectory(*lpPathName, NULL);
	SetFileAttributes(*lpPathName, FILE_ATTRIBUTE_HIDDEN);

	return 0;
}

int libsunc_create_sess_id_file() {
	/*
	unsigned char* uuid;
	unsigned char* filename;

	libsunc_gen_id_uuid(uuid);
	memcpy(filename, "sunc-id", sizeof(char[8]));
	memcpy(filename + 8, uuid, sizeof(char[128]));

	char *filePath;
	strcat(filePath, "S:\\");
	strcat(filePath, (char*)uuid);
	strcat(filePath, "\\");
	strcat(filePath, (char*)filename);
	*/
	// FILE *sess_id_file = fopen((char*)("S:\\%s\\%s", uuid, filename), "w");
	char *filePath;
	libsunc_get_sess_id_file_path(filePath);

	FILE* sess_id_file = fopen(filePath, "w");
	fclose(sess_id_file);

	LPCWSTR winPath = (LPCWSTR)filePath;
	SetFileAttributes(winPath, FILE_ATTRIBUTE_HIDDEN);

	return 0;
}

int libsunc_create_sess_msg_file(unsigned char *uuid) {
	/*
	unsigned char* uuid;
	unsigned char* filename;

	libsunc_gen_id_uuid(uuid);
	memcpy(filename, "sunc-sess", sizeof(char[10]));
	memcpy(filename + 10, uuid, sizeof(char[128]));

	char* filePath;
	strcat(filePath, "S:\\");
	strcat(filePath, (char*)uuid);
	strcat(filePath, "\\");
	strcat(filePath, (char*)filename);

	// FILE* sess_msg_file = fopen((char*)("S:\\%s\\%s", uuid, filename), "w");
	*/
	char *filePath;
	libsunc_get_sess_msg_file_path(filePath, uuid);

	FILE* sess_msg_file = fopen(filePath, "w");
	fclose(sess_msg_file);

	LPCWSTR winPath = (LPCWSTR)filePath;
	SetFileAttributes(winPath, FILE_ATTRIBUTE_HIDDEN);

	return 0;
}

int libsunc_write_pub_key(EVP_PKEY *key, unsigned char *uuid) {
	/*
	unsigned char* uuid;
	unsigned char* filename;

	libsunc_gen_id_uuid(uuid);
	memcpy(filename, "pub", sizeof(char[4]));
	memcpy(filename + 4, uuid, sizeof(char[128]));

	char* filePath;
	strcat(filePath, "S:\\");
	strcat(filePath, (char*)uuid);
	strcat(filePath, "\\");
	strcat(filePath, (char*)filename);

	// FILE* sess_msg_file = fopen((char*)("S:\\%s\\%s", uuid, filename), "w");
	*/
	char *filePath;
	libsunc_get_pub_key_file_path(filePath, uuid);

	FILE* pub_key_file = fopen(filePath, "w");
	libsunc_gen_pub_key(pub_key_file, key);
	fclose(pub_key_file);

	LPCWSTR winPath = (LPCWSTR)filePath;
	SetFileAttributes(winPath, FILE_ATTRIBUTE_HIDDEN);

	return 0;
}

int libsunc_status_set(char status) {
	char *filePath;
	libsunc_get_sess_id_file_path(filePath);

	FILE *sess_id_file = fopen(filePath, "w");
	
	switch (status) {
		case 'o' :
			fputs("[open]", sess_id_file);
			break;

		case 'c' :
			fputs("[closed]", sess_id_file);
			break;

		case 'i':
			fputs("[idle]", sess_id_file);
			break;

		case 'd':
			fputs("[debug]", sess_id_file);
			break;

		case 'e':
			fputs("[error]", sess_id_file);
			break;

		default :
			fputs("[closed]", sess_id_file);
			break;
	}

	fclose(sess_id_file);

	return 0;
}

int libsunc_status_open() {
	libsunc_status_set('o');
	return 0;
}

int libsunc_status_cls() {
	libsunc_status_set('c');
	return 0;
}

int libsunc_status_idle() {
	libsunc_status_set('i');
	return 0;
}

int libsunc_status_deb() {
	libsunc_status_set('d');
	return 0;
}

int libsunc_status_err() {
	libsunc_status_set('e');
	return 0;
}

int libsunc_est_conn(unsigned char *client, EVP_PKEY *key, EVP_PKEY *clientKey) {
	unsigned char* clientHash = libsunc_auto_hash(client);
	libsunc_create_sess_folder(clientHash);
	
	libsunc_write_pub_key(key, clientHash);

	char *sess_msg_file_path;
	libsunc_get_sess_msg_file_path(sess_msg_file_path, clientHash);

	FILE *sess_msg_file;

	for (;;) {
		if (sess_msg_file = fopen(sess_msg_file_path, "r")) {
			fclose(sess_msg_file);
			break;
		}

		_sleep(1000);
	}
	
	// decrypt and read file contents. Encrypt and replace

	for (;;) {
		sess_msg_file = fopen(sess_msg_file_path, "r");

		char *buff;
		fgets(buff, 50, sess_msg_file);

		if (!strcmp(buff, "[SUCCESS]")) {
			fclose(sess_msg_file);
			break;
		}

		_sleep(1000);
	}

	sess_msg_file = fopen(sess_msg_file_path, "w");
	fputs("", sess_msg_file);
	fclose(sess_msg_file);

	return 0;
}

int libsunc_acc_conn(EVP_PKEY *key) {
	unsigned char *uuid;
	libsunc_gen_id_uuid(uuid);

	libsunc_create_sess_msg_file(uuid);

	char *sess_msg_file_path;
	libsunc_get_sess_msg_file_path(sess_msg_file_path, uuid);

	FILE *sess_msg_file = fopen(sess_msg_file_path, "w");
	time_t dt = time(0);
	char* dt_str = ctime(&dt);

	char *buff;

	strcpy(buff, dt_str);
	strcpy(buff, "0.1\n");
	strcpy(buff, getenv("USERNAME"));
	strcpy(buff, "\n256\n");
	// strncpy(dt_str, dt_str, strlen(dt_str) - 2);
	
	fputs(buff, sess_msg_file);

	fclose(sess_msg_file);

	for (;;) {
		sess_msg_file = fopen(sess_msg_file_path, "r");

		char* msg;
		fgets(msg, 50, sess_msg_file);

		if (strcmp(buff, msg)) {
			fclose(sess_msg_file);
			break;
		}

		_sleep(1000);
		
	}

	sess_msg_file = fopen(sess_msg_file_path, "w");
	fputs("[SUCCESS]", sess_msg_file);
	fclose(sess_msg_file);

	return 0;
}

int libsunc_write_msg(char *msg) {
	if (strlen(msg) != 256) {
		printf("Message not correct length\n");
		return 1;
	}

	unsigned char* uuid;
	libsunc_gen_id_uuid(uuid);

	char *sess_msg_file_path;
	libsunc_get_sess_msg_file_path(sess_msg_file_path, uuid);

	FILE* sess_msg_file = fopen(sess_msg_file_path, "a");
	fputs(msg, sess_msg_file);
	fclose(sess_msg_file);
	
	return 0;
}

int libsunc_read_msg(char* msg) {
	unsigned char* uuid;
	libsunc_gen_id_uuid(uuid);

	char *sess_msg_file_path;
	libsunc_get_sess_msg_file_path(sess_msg_file_path, uuid);

	char* buff;
	FILE* sess_msg_file = fopen(sess_msg_file_path, "r");
	fgets(buff, 999999, sess_msg_file);
	msg = new char[128];
	
	for (unsigned int i = 0; i < 128; i++) {
		msg[i] = buff[strlen(buff) - 128 + i];
	}

	fclose(sess_msg_file);
	return 0;
}

int libsunc_enc_msg(unsigned char* plainText, int plainTextLen, unsigned char* enc, EVP_PKEY **pubKey, unsigned char **encKey, int *encKeyLen, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	int encLen;
	int len;

	ctx = EVP_CIPHER_CTX_new();

	EVP_SealInit(ctx, EVP_aes_256_cbc(), encKey, encKeyLen, iv, pubKey, 1);
	EVP_SealUpdate(ctx, enc, &len, plainText, plainTextLen);

	encLen += len;

	EVP_SealFinal(ctx, enc + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	return encLen;
}

int libsunc_dec_msg(unsigned char* enc, int encLen, unsigned char* plainText, EVP_PKEY* privKey, unsigned char* encKey, int encKeyLen, unsigned char* iv) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plainTextLen;

	ctx = EVP_CIPHER_CTX_new();

	EVP_OpenInit(ctx, EVP_aes_256_cbc(), encKey, encKeyLen, iv, privKey);
	EVP_OpenUpdate(ctx, plainText, &len, enc, encLen);

	plainTextLen = len;

	EVP_CIPHER_CTX_free(ctx);

	return plainTextLen;
}

/*
static int libsunc_gen_priv_key(EVP_PKEY *key) {
	EVP_PKEY* pkey;
	pkey = EVP_PKEY_new();

	BIGNUM *bn;
	bn = BN_new();
	BN_set_word(bn, RSA_F4);

	RSA* rsa;
	rsa = RSA_new();
	RSA_generate_key_ex(
		rsa,
		2048,
		bn,
		NULL
	);

	EVP_PKEY_assign_RSA(pkey, rsa);
	key = pkey;
	return 0;
}

*/


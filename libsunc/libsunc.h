#pragma once

#ifndef LIBSUNC_H
#define LIBSUNC_H

#ifdef LIBSUNC_EXPORTS
#define LIBSUNC_API __declspec(dllexport)
#else
#define LIBSUNC_API __declspec(dllimport)
#endif

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/ssl2.h"
#include "openssl/ssl3.h"
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/pem.h"

#include <iostream>
#include <ostream>
#include <string>
#include <algorithm>
#include <fileapi.h>
#include <stdlib.h>
#include <ctime>

extern "C" LIBSUNC_API void libsunc_init();
extern "C" LIBSUNC_API void libsunc_uninit();

extern "C" LIBSUNC_API int libsunc_auto_hash(unsigned char *, unsigned char *);
extern "C" LIBSUNC_API int libsunc_auto_unhash(unsigned char *, unsigned char *, unsigned char *);

extern "C" LIBSUNC_API int libsunc_read_pub_key(char *, EVP_PKEY *);

extern "C" LIBSUNC_API int libsunc_gen_uuid(char *);
extern "C" LIBSUNC_API int libsunc_gen_id_uuid(unsigned char *);
extern "C" LIBSUNC_API int libsunc_gen_sess_uuid(char *);

extern "C" LIBSUNC_API int libsunc_gen_priv_key(EVP_PKEY *);
extern "C" LIBSUNC_API int libsunc_gen_pub_key(FILE *, EVP_PKEY *);

extern "C" LIBSUNC_API int libsunc_get_sess_id_folder_c(char *);
extern "C" LIBSUNC_API int libsunc_get_sess_id_folder_win(LPCWSTR *);
extern "C" LIBSUNC_API int libsunc_get_sess_folder_c(char *, unsigned char *);
extern "C" LIBSUNC_API int libsunc_get_sess_folder_win(LPCWSTR *, unsigned char *);
extern "C" LIBSUNC_API int libsunc_get_sess_id_file_path(char *);
extern "C" LIBSUNC_API int libsunc_get_sess_msg_file_path(char *, unsigned char *);
extern "C" LIBSUNC_API int libsunc_get_pub_key_file_path(char*, unsigned char*);
extern "C" LIBSUNC_API int libsunc_create_sess_id_folder();
extern "C" LIBSUNC_API int libsunc_create_sess_folder(unsigned char *);
extern "C" LIBSUNC_API int libsunc_create_sess_id_file();
extern "C" LIBSUNC_API int libsunc_create_sess_msg_file(unsigned char *);
extern "C" LIBSUNC_API int libsunc_write_pub_key(EVP_PKEY *, unsigned char *);

extern "C" LIBSUNC_API int libsunc_status_set(char);
extern "C" LIBSUNC_API int libsunc_status_open();
extern "C" LIBSUNC_API int libsunc_status_cls();
extern "C" LIBSUNC_API int libsunc_status_idle();
extern "C" LIBSUNC_API int libsunc_status_deb();
extern "C" LIBSUNC_API int libsunc_status_err();

extern "C" LIBSUNC_API int libsunc_est_conn(unsigned char *, EVP_PKEY *, EVP_PKEY *);
extern "C" LIBSUNC_API int libsunc_acc_conn(EVP_PKEY *);

extern "C" LIBSUNC_API int libsunc_write_msg(char *);
extern "C" LIBSUNC_API int libsunc_read_msg(char *);

extern "C" LIBSUNC_API int libsunc_enc_msg(unsigned char *, int, unsigned char *, EVP_PKEY **, unsigned char ** , int * , unsigned char *);
extern "C" LIBSUNC_API int libsunc_dec_msg(unsigned char *, int, unsigned char *, EVP_PKEY *, unsigned char *, int, unsigned char *);

#endif
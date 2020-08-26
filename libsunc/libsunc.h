#pragma once

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

static void libsunc_init();
static void libsunc_uninit();

static char* libsunc_auto_hash();
static char* libsunc_auto_unhash();

static int libsunc_read_pub_key(char *, EVP_PKEY);

static int libsunc_gen_uuid();
static int libsunc_gen_sess_uuid();
static int libsunc_gen_id_uuid();

static int* libsunc_gen_priv_key();
static int* libsunc_gen_pub_key();

static int libsunc_get_sess_folder(char *);
static int libsunc_create_sess_folder();
static int libsunc_create_sess_id_file();
static int libsunc_create_sess_msg_file();
static int libsunc_write_pub_key();

static int libsunc_status_set(char);
static int libsunc_status_open();
static int libsunc_status_cls();
static int libsunc_status_idle();
static int libsunc_status_deb();
static int libsunc_status_err();

static int libsunc_est_conn(char*);
static int libsunc_acc_conn(char*);

static int libsunc_write_msg();
static int libsunc_read_msg();

static int libsunc_enc_msg();
static int libsunc_dec_msg();




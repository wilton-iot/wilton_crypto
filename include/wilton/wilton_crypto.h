/*
 * Copyright 2018, alex at staticlibs.net
 * Copyright 2018, mike at myasnikov.mike@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WILTON_CRYPTO_H
#define WILTON_CRYPTO_H

#include "wilton/wilton.h"

#ifdef __cplusplus
extern "C" {
#endif

char* wilton_crypto_sha256(
        const char* file_path,
        int file_path_len,
        char** result_set_out,
        int* result_set_len_out);

char* wilton_crypto_aes_create_crypt_key(
        const char* secret,
        int secret_len,
        char** key_out,
        int* key_len_out,
        char** iv_out,
        int* iv_len_out);

char* wilton_crypto_aes_encrypt(
        const char* file_path,
        int file_path_len,
        const char* crypt_key,
        int crypt_key_len,
        const char* init_vec,
        int init_vec_len,
        const char* dest_file_path,
        int dest_file_path_len);

char* wilton_crypto_aes_decrypt(
        const char* file_path,
        int file_path_len,
        const char* crypt_key,
        int crypt_key_len,
        const char* init_vec,
        int init_vec_len,
        const char* dest_file_path,
        int dest_file_path_len);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_CRYPTO_H */

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

#include "wilton/wilton_crypto.h"

#include "openssl/evp.h"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/crypto.hpp"

#include "wilton/support/alloc.hpp"
#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.crypto");

} // namespace

char* wilton_crypto_sha256 (const char* file_path, int file_path_len, char** result_set_out,
        int* result_set_len_out) /* noexcept */ {
    if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (nullptr == result_set_out) return wilton::support::alloc_copy(TRACEMSG("Null 'result_set_out' parameter specified"));
    if (nullptr == result_set_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'result_set_len_out' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    try {
        auto file_path_str = std::string(file_path, static_cast<uint16_t> (file_path_len));

        // call
        wilton::support::log_debug(logger, "Computing SHA256 for file, path: [" + file_path_str + "] ...");
        auto source = sl::tinydir::file_source(file_path_str);
        auto sha_source = sl::crypto::make_sha256_source<sl::tinydir::file_source>(std::move(source));
        auto sink = sl::io::null_sink();
        sl::io::copy_all(sha_source, sink);
        auto hash = sha_source.get_hash();
        wilton::support::log_debug(logger, "SHA256 computed, value: [" + hash + "] ...");

        *result_set_out = wilton::support::alloc_copy(hash);
        *result_set_len_out = static_cast<int>(hash.length());
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_crypto_aes_create_crypt_key(const char* secret, int secret_len, char** key_out,
        int* key_len_out, char** iv_out, int* iv_len_out) /* noexcept */ {
    if (nullptr == secret) return wilton::support::alloc_copy(TRACEMSG("Null 'secret' parameter specified"));
    if (!sl::support::is_uint16_positive(secret_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'secret_len' parameter specified: [" + sl::support::to_string(secret_len) + "]"));
    if (nullptr == key_out) return wilton::support::alloc_copy(TRACEMSG("Null 'key_out' parameter specified"));
    if (nullptr == key_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'key_len_out' parameter specified"));
    if (nullptr == iv_out) return wilton::support::alloc_copy(TRACEMSG("Null 'iv_out' parameter specified"));
    if (nullptr == iv_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'iv_len_out' parameter specified"));
    try {
        auto secret_str = std::string(secret, static_cast<uint16_t>(secret_len));
        auto sha256 = [](const std::string& input) {
            auto src = sl::io::string_source(input);
            auto dest = sl::io::null_sink();
            auto sink = sl::crypto::make_sha256_sink(dest);
            sl::io::copy_all(src, sink);
            return sink.get_hash();
        };
        auto hash = sha256(secret_str);
        auto key = sha256(secret_str + hash).substr(0, 64); // full string
        auto iv = sha256(hash + secret_str).substr(0, 32);

        auto key_bin = sl::io::string_from_hex(key);
        auto iv_bin = sl::io::string_from_hex(iv);

        auto key_buf = wilton::support::make_string_buffer(key_bin);
        auto iv_buf = wilton::support::make_string_buffer(iv_bin);

        *key_out = key_buf.data();
        *key_len_out = key_buf.size_int();
        *iv_out = iv_buf.data();
        *iv_len_out = iv_buf.size_int();

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_crypto_aes_encrypt(const char* file_path, int file_path_len,
        const char* crypt_key, int crypt_key_len,
        const char* init_vec, int init_vec_len,
        const char* dest_file_path, int dest_file_path_len) /* noexcept */ {
    if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    if (nullptr == crypt_key) return wilton::support::alloc_copy(TRACEMSG("Null 'crypt_key' parameter specified"));
    if (!sl::support::is_uint16_positive(crypt_key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'crypt_key_len' parameter specified: [" + sl::support::to_string(crypt_key_len) + "]"));
    if (nullptr == init_vec) return wilton::support::alloc_copy(TRACEMSG("Null 'init_vec' parameter specified"));
    if (!sl::support::is_uint16_positive(init_vec_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'init_vec_len' parameter specified: [" + sl::support::to_string(init_vec_len) + "]"));
    if (nullptr == dest_file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'dest_file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(dest_file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'dest_file_path_len' parameter specified: [" + sl::support::to_string(dest_file_path_len) + "]"));
    try {
        auto file_path_str = std::string(file_path, static_cast<uint16_t>(file_path_len));
        auto crypt_key_str = std::string(crypt_key, static_cast<uint16_t>(crypt_key_len));
        auto init_vec_str = std::string(init_vec, static_cast<uint16_t>(init_vec_len));
        auto dest_file_path_str = std::string(dest_file_path, static_cast<uint16_t>(dest_file_path_len));

        auto crypt_key_bin = sl::io::string_from_hex(crypt_key_str);
        auto init_vec_bin = sl::io::string_from_hex(init_vec_str);

        wilton::support::log_debug(logger, "Encrypting file, path: [" + file_path_str + "] ...");
        auto src = sl::tinydir::file_source(file_path_str);
        auto fsink = sl::tinydir::file_sink(dest_file_path_str);
        auto bsink = sl::io::make_buffered_sink(fsink);
        auto sink = sl::crypto::make_encrypt_sink(bsink, EVP_aes_256_cbc(),
                crypt_key_bin, init_vec_bin);
        sl::io::copy_all(src, sink);
        wilton::support::log_debug(logger, "Encrypted file written, path: [" + dest_file_path_str + "] ...");

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_crypto_aes_decrypt(const char* file_path, int file_path_len,
        const char* crypt_key, int crypt_key_len,
        const char* init_vec, int init_vec_len,
        const char* dest_file_path, int dest_file_path_len) /* noexcept */ {
    if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    if (nullptr == crypt_key) return wilton::support::alloc_copy(TRACEMSG("Null 'crypt_key' parameter specified"));
    if (!sl::support::is_uint16_positive(crypt_key_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'crypt_key_len' parameter specified: [" + sl::support::to_string(crypt_key_len) + "]"));
    if (nullptr == init_vec) return wilton::support::alloc_copy(TRACEMSG("Null 'init_vec' parameter specified"));
    if (!sl::support::is_uint16_positive(init_vec_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'init_vec_len' parameter specified: [" + sl::support::to_string(init_vec_len) + "]"));
    if (nullptr == dest_file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'dest_file_path' parameter specified"));
    if (!sl::support::is_uint16_positive(dest_file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'dest_file_path_len' parameter specified: [" + sl::support::to_string(dest_file_path_len) + "]"));
    try {
        auto file_path_str = std::string(file_path, static_cast<uint16_t>(file_path_len));
        auto crypt_key_str = std::string(crypt_key, static_cast<uint16_t>(crypt_key_len));
        auto init_vec_str = std::string(init_vec, static_cast<uint16_t>(init_vec_len));
        auto dest_file_path_str = std::string(dest_file_path, static_cast<uint16_t>(dest_file_path_len));

        auto crypt_key_bin = sl::io::string_from_hex(crypt_key_str);
        auto init_vec_bin = sl::io::string_from_hex(init_vec_str);

        wilton::support::log_debug(logger, "Decrypting file, path: [" + file_path_str + "] ...");
        auto src = sl::tinydir::file_source(file_path_str);
        auto fsink = sl::tinydir::file_sink(dest_file_path_str);
        auto bsink = sl::io::make_buffered_sink(fsink);
        auto sink = sl::crypto::make_decrypt_sink(bsink, EVP_aes_256_cbc(),
                crypt_key_bin, init_vec_bin);
        sl::io::copy_all(src, sink);
        wilton::support::log_debug(logger, "Decrypted file written, path: [" + dest_file_path_str + "] ...");

        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}
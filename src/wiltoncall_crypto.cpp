/*
 * Copyright 2017, alex at staticlibs.net
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

/* 
 * File:   wiltoncall_crypto.cpp
 * Author: alex
 *
 * Created on December 3, 2017, 6:40 PM
 */

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"

#include "staticlib/support.hpp"
#include "staticlib/crypto.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/json.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"

#include "wilton/wilton_crypto.h"

namespace wilton {
namespace crypto {

support::buffer crypto_hash256(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rfile = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("filePath" == name) {
            rfile = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rfile.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'filePath' not specified"));

    const std::string& file_path = rfile.get();
    char* hash = nullptr;
    int hash_len = 0;
    char* err = wilton_crypto_sha256(file_path.c_str(),
           static_cast<int>(file_path.size()),
           std::addressof(hash), std::addressof(hash_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(hash, hash_len);
}

support::buffer crypto_aes(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rop = std::ref(sl::utils::empty_string());
    auto rfile = std::ref(sl::utils::empty_string());
    auto rdest = std::ref(sl::utils::empty_string());
    auto rkey = std::ref(sl::utils::empty_string());
    auto riv = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("operation" == name) {
            rop = fi.as_string_nonempty_or_throw(name);
        } else if ("filePath" == name) {
            rfile = fi.as_string_nonempty_or_throw(name);
        } else if ("destFilePath" == name) {
            rdest = fi.as_string_nonempty_or_throw(name);
        } else if ("cryptKey" == name) {
            rkey = fi.as_string_nonempty_or_throw(name);
        } else if ("initVec" == name) {
            riv = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rop.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'operation' not specified"));
    if (rfile.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'filePath' not specified"));
    if (rdest.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'destFilePath' not specified"));
    if (rkey.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'cryptKey' not specified"));
    if (riv.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'initVec' not specified"));
    const std::string& op = rop.get();
    const std::string& file = rfile.get();
    const std::string& dest = rdest.get();
    const std::string& key = rkey.get();
    const std::string& iv = riv.get();

    // call wilton
    char* err = nullptr;
    if ("encrypt" == op) {
        err = wilton_crypto_aes_encrypt(file.c_str(), static_cast<int>(file.size()),
                key.c_str(), static_cast<int>(key.size()),
                iv.c_str(), static_cast<int>(iv.size()),
                dest.c_str(), static_cast<int>(dest.size()));
    } else if ("decrypt" == op) {
        err = wilton_crypto_aes_decrypt(file.c_str(), static_cast<int>(file.size()),
                key.c_str(), static_cast<int>(key.size()),
                iv.c_str(), static_cast<int>(iv.size()),
                dest.c_str(), static_cast<int>(dest.size()));
    } else {
        throw support::exception(TRACEMSG(
                "Invalid parameter 'operation' specified," +
                " value: [" + rop.get() + "]," +
                " must be one of: [encrypt, decrypt]"));
    }
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::make_null_buffer();
}

support::buffer aes_create_crypt_key(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    auto rsecret = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("secret" == name) {
            rsecret = fi.as_string_nonempty_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rsecret.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'secret' not specified"));
    const std::string& secret = rsecret.get();

    // call wilton
    char* key = nullptr;
    int key_len = 0;
    char* iv = nullptr;
    int iv_len = 0;
    char* err = wilton_crypto_aes_create_crypt_key(secret.c_str(), static_cast<int>(secret.size()),
                std::addressof(key), std::addressof(key_len),
                std::addressof(iv), std::addressof(iv_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    auto deferred = sl::support::defer([key, iv]() STATICLIB_NOEXCEPT {
        wilton_free(key);
        wilton_free(iv);
    });
    return support::make_json_buffer({
        { "cryptKey", std::string(key, static_cast<size_t>(key_len)) },
        { "initVec", std::string(iv, static_cast<size_t>(iv_len)) }
    });
}

} // namespace crypto
} // namespace wilton


extern "C" char* wilton_module_init() {
    try {
        // register calls
        wilton::support::register_wiltoncall("crypto_hash256", wilton::crypto::crypto_hash256);
        wilton::support::register_wiltoncall("crypto_aes", wilton::crypto::crypto_aes);
        wilton::support::register_wiltoncall("crypto_aes_create_crypt_key", wilton::crypto::aes_create_crypt_key);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

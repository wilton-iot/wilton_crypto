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


//#include <array>

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

support::buffer get_file_hash256(sl::io::span<const char> data) {
    // json parse
    auto json = sl::json::load(data);
    int buffer_len = 1024;
    auto rfile = std::ref(sl::utils::empty_string());
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("bufferLength" == name) {
            buffer_len = fi.as_int32_or_throw(name);
        } else if ("filePath" == name) {
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
    char* err = wilton_crypto_get_file_hash256(file_path.c_str(), file_path.size(), buffer_len,
                                std::addressof(hash), std::addressof(hash_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    return support::wrap_wilton_buffer(hash, hash_len);
}

} // namespace crypto
} // namespace wilton


extern "C" char* wilton_module_init() {
    try {
        // register calls
        wilton::support::register_wiltoncall("get_file_hash256", wilton::crypto::get_file_hash256);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

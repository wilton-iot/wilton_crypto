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

namespace wilton {
namespace crypto {

support::buffer get_file_hash(sl::io::span<const char> data) {
    auto file_path = std::string(data.begin(), data.size());

    const size_t buffer_len = 1024;
    std::array<char, buffer_len> buf;
    auto sink = sl::io::string_sink();

    // call
    auto tpath = sl::tinydir::path(file_path);
    auto source = tpath.open_read();
    auto sha_source = sl::crypto::make_sha256_source<sl::tinydir::file_source>(std::move(source));

    sl::io::copy_all(sha_source, sink, buf);
    auto hash = sha_source.get_hash();

    return support::make_string_buffer(hash);
}

} // namespace crypto
} // namespace wilton


extern "C" char* wilton_module_init() {
    try {
        // register calls
        wilton::support::register_wiltoncall("get_file_hash", wilton::crypto::get_file_hash);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

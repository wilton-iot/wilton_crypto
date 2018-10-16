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

#include <vector>

#include "wilton/wilton_crypto.h"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/crypto.hpp"

#include "wilton/support/alloc.hpp"
#include "wilton/support/exception.hpp"

char* wilton_crypto_get_file_hash  /* noexcept */(
        const char* file_path,
        int file_path_len,
        int read_buffer_size,
        char** result_set_out,
        int* result_set_len_out){
	if (nullptr == file_path) return wilton::support::alloc_copy(TRACEMSG("Null 'file_path' parameter specified"));
	if (nullptr == result_set_out) return wilton::support::alloc_copy(TRACEMSG("Null 'result_set_out' parameter specified"));
	if (nullptr == result_set_len_out) return wilton::support::alloc_copy(TRACEMSG("Null 'result_set_len_out' parameter specified"));
    if (!sl::support::is_uint16_positive(file_path_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(file_path_len) + "]"));
    if (!sl::support::is_uint32_positive(read_buffer_size)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'file_path_len' parameter specified: [" + sl::support::to_string(read_buffer_size) + "]"));
	try {
        auto file_path_str = std::string(file_path, static_cast<uint32_t> (file_path_len));
        std::vector<char> buf(read_buffer_size);
        auto sink = sl::io::string_sink();

        // call
        auto tpath = sl::tinydir::path(file_path_str);
        auto source = tpath.open_read();
        auto sha_source = sl::crypto::make_sha256_source<sl::tinydir::file_source>(std::move(source));

        sl::io::copy_all(sha_source, sink, buf);
        auto hash = sha_source.get_hash();

        *result_set_out = wilton::support::alloc_copy(hash);
        *result_set_len_out = static_cast<int>(hash.length());
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }  
}

/* 
 * File:   wiltoncall_crypto.cpp
 * Author: alex
 *
 * Created on December 3, 2017, 6:40 PM
 */

#include "staticlib/support.hpp"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"

extern "C" char* wilton_module_init() {
    //try {
        // register calls
        return nullptr;
    //} catch (const std::exception& e) {
    //    return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    //}
}

/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace hexdump {
using Byte = unsigned char;

template<Byte bytes_per_row = 16, typename InputIterator>
[[nodiscard]] std::string hexdump(InputIterator begin, const InputIterator end)
{
    static_assert(bytes_per_row > 0);
    static constexpr std::pair<Byte, Byte> printable{ 32, 126 };
    std::uint32_t                          offset = 0;
    std::ostringstream                     output;
    bool                                   first = true;
    output << std::hex << std::setfill('0');
    do {
        if (first) {
            first = false;
        } else {
            output << "\n";
        }
        output << std::setw(8) << offset << "  ";
        offset += bytes_per_row;
        auto it = begin;
        for (Byte i = 0; i < bytes_per_row; ++i) {
            if (i == 8) {
                output << ' ';
            }
            if (it != end) {
                output << std::setw(2) << static_cast<std::uint32_t>(*it) << ' ';
                ++it;
            } else {
                output << "   ";
            }
        }
        output << " ";
        for (Byte i = 0; i < bytes_per_row; ++i) {
            if (begin != end) {
                output << (((static_cast<std::uint32_t>(*begin) >= printable.first) &&
                            (static_cast<std::uint32_t>(*begin) <= printable.second))
                             ? static_cast<char>(*begin) // NOSONAR intentional conversion to plain char
                             : '.');
                ++begin;
            } else {
                output << ' ';
            }
        }
    } while (begin != end);
    return output.str();
}

[[nodiscard]] auto hexdump(const auto& cont) { return hexdump(std::begin(cont), std::end(cont)); }

[[nodiscard]] inline auto hexdump(const void* const data, const std::size_t size)
{
    return hexdump(static_cast<const Byte*>(data), static_cast<const Byte*>(data) + size);
}
} // namespace hexdump

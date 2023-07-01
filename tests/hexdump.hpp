/// This software is distributed under the terms of the MIT License.
/// Copyright (C) OpenCyphal Development Team  <opencyphal.org>
/// Copyright Amazon.com Inc. or its affiliates.
/// SPDX-License-Identifier: MIT
/// Author: Pavel Kirienko <pavel@opencyphal.org>

#include <string>
#include <sstream>
#include <iomanip>

namespace hexdump
{
template <std::uint8_t BytesPerRow = 16, typename InputIterator>
[[nodiscard]] std::string hexdump(InputIterator begin, const InputIterator end)
{
    static_assert(BytesPerRow > 0);
    static constexpr std::pair<std::uint8_t, std::uint8_t> PrintableASCIIRange{32, 126};
    std::uint32_t                                          offset = 0;
    std::ostringstream                                     output;
    bool                                                   first = true;
    output << std::hex << std::setfill('0');
    do
    {
        if (first)
        {
            first = false;
        }
        else
        {
            output << std::endl;
        }
        output << std::setw(8) << offset << "  ";
        offset += BytesPerRow;
        auto it = begin;
        for (std::uint8_t i = 0; i < BytesPerRow; ++i)
        {
            if (i == 8)
            {
                output << ' ';
            }

            if (it != end)
            {
                output << std::setw(2) << static_cast<std::uint32_t>(*it) << ' ';
                ++it;
            }
            else
            {
                output << "   ";
            }
        }
        output << " ";
        for (std::uint8_t i = 0; i < BytesPerRow; ++i)
        {
            if (begin != end)
            {
                output << (((static_cast<std::uint32_t>(*begin) >= PrintableASCIIRange.first) &&
                            (static_cast<std::uint32_t>(*begin) <= PrintableASCIIRange.second))
                               ? static_cast<char>(*begin)  // NOSONAR intentional conversion to plain char
                               : '.');
                ++begin;
            }
            else
            {
                output << ' ';
            }
        }
    } while (begin != end);
    return output.str();
}

[[nodiscard]] auto hexdump(const auto& cont)
{
    return hexdump(std::begin(cont), std::end(cont));
}

[[nodiscard]] inline auto hexdump(const void* const data, const std::size_t size)
{
    return hexdump(static_cast<const std::uint8_t*>(data), static_cast<const std::uint8_t*>(data) + size);
}
}  // namespace hexdump

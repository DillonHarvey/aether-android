#include "string_memory.hpp"
#include <vector>
#include <algorithm>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint64_t limit = 1024 * 1024;
struct Failure { Fault fault; std::string_view reason; };
[[noreturn]] void fail(Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
void bounded(std::uint64_t count) {
    if (count > limit) fail(Fault::unsupported_service, "native string/memory operation exceeds 1 MiB profile");
}
std::uint8_t read_byte(a64::GuestMemory &memory, Address address, std::uint64_t offset) {
    if (offset >= limit) fail(Fault::unsupported_service, "native string scan exceeds 1 MiB profile");
    std::array<std::uint8_t, 1> value{};
    if (address >= a64::GuestMemory::address_limit || offset >= a64::GuestMemory::address_limit - address ||
        !memory.read(address + offset, value))
        fail(Fault::read, "native string/memory source is outside readable guest memory");
    return value[0];
}
void writable(a64::GuestMemory &memory, Address address, std::uint64_t count) {
    if (count && (address >= a64::GuestMemory::address_limit || count > a64::GuestMemory::address_limit - address ||
                  !memory.accessible(address, static_cast<std::size_t>(count), a64::Permission::write)))
        fail(Fault::write, "native string/memory destination is outside writable guest memory");
}
std::vector<std::uint8_t> string(a64::GuestMemory &memory, Address address) {
    std::vector<std::uint8_t> result;
    for (std::uint64_t i = 0;; ++i) {
        const auto byte = read_byte(memory, address, i);
        if (!byte) return result;
        result.push_back(byte);
    }
}
std::vector<std::size_t> prefix_table(const std::vector<std::uint8_t> &needle) {
    std::vector<std::size_t> prefix(needle.size());
    for (std::size_t i = 1, matched = 0; i < needle.size(); ++i) {
        while (matched && needle[i] != needle[matched]) matched = prefix[matched - 1];
        if (needle[i] == needle[matched]) ++matched;
        prefix[i] = matched;
    }
    return prefix;
}
Address search(a64::GuestMemory &memory, Address haystack, std::uint64_t count,
               const std::vector<std::uint8_t> &needle, bool text) {
    if (needle.empty()) return haystack;
    const auto prefix = prefix_table(needle);
    for (std::uint64_t i = 0, matched = 0; text || i < count; ++i) {
        const auto byte = read_byte(memory, haystack, i);
        if (text && !byte) return 0;
        while (matched && byte != needle[static_cast<std::size_t>(matched)])
            matched = prefix[static_cast<std::size_t>(matched - 1)];
        if (byte == needle[static_cast<std::size_t>(matched)]) ++matched;
        if (matched == needle.size()) return haystack + i + 1 - matched;
    }
    return 0;
}
} // namespace

Fault NativeStringMemory::invoke(StringMemoryOperation operation, std::array<std::uint64_t, 31> &r) noexcept {
    rejection_ = {};
    try {
        const auto first = r[0], second = r[1], count = r[2];
        using Op = StringMemoryOperation;
        switch (operation) {
        case Op::copy_end: {
            auto bytes = string(memory_, second);
            const auto length = static_cast<std::uint64_t>(bytes.size());
            bytes.push_back(0);
            writable(memory_, first, length + 1);
            if (!memory_.write(first, bytes))
                fail(Fault::write, "native stpcpy destination write failed");
            r[0] = first + length;
            return Fault::none;
        }
        case Op::concatenate_n: {
            // n bounds source consumption, not a padding or allocation request.
            // With no bytes to append, neither guest pointer needs accessing.
            if (!count) return Fault::none;
            std::uint64_t length = 0;
            while (read_byte(memory_, first, length)) ++length;
            std::vector<std::uint8_t> bytes;
            for (std::uint64_t i = 0; i < count; ++i) {
                const auto byte = read_byte(memory_, second, i);
                if (!byte) break;
                bytes.push_back(byte);
            }
            // Include the required NUL in the resulting string's bounded span.
            bounded(length + static_cast<std::uint64_t>(bytes.size()) + 1);
            bytes.push_back(0);
            const auto output = first + length; // The terminating-byte read validated this addition.
            writable(memory_, output, static_cast<std::uint64_t>(bytes.size()));
            if (!memory_.write(output, bytes))
                fail(Fault::write, "native strncat destination write failed");
            // Preserve the original destination in x0, with no NUL padding.
            return Fault::none;
        }
        case Op::span_accept:
        case Op::span_reject:
        case Op::find_any: {
            const auto members = string(memory_, second);
            std::array<bool, 256> present{};
            for (const auto byte : members) present[byte] = true;
            if (members.empty() && operation != Op::span_reject) {
                r[0] = 0;
                return Fault::none;
            }
            for (std::uint64_t i = 0;; ++i) {
                const auto byte = read_byte(memory_, first, i);
                const bool matched = present[byte];
                if (!byte || (operation == Op::span_accept ? !matched : matched)) {
                    r[0] = operation == Op::find_any ? (byte ? first + i : 0) : i;
                    return Fault::none;
                }
            }
        }
        case Op::length_n: {
            // maxlen is a read bound, not an up-front transfer/allocation request.
            std::uint64_t length=0;
            while(length<second && read_byte(memory_,first,length))++length;
            r[0]=length;return Fault::none;
        }
        case Op::compare:
        case Op::compare_n:
        case Op::compare_bytes: {
            const bool text = operation != Op::compare_bytes, unbounded = operation == Op::compare;
            if (!unbounded) bounded(count);
            std::uint32_t result = 0;
            for (std::uint64_t i = 0; unbounded || i < count; ++i) {
                const auto left = read_byte(memory_, first, i), right = read_byte(memory_, second, i);
                if (left != right) {
                    result = static_cast<std::uint32_t>(static_cast<int>(left) - static_cast<int>(right));
                    break;
                }
                if (text && !left) break;
            }
            r[0] = result;
            return Fault::none;
        }
        case Op::find_char:
        case Op::find_last_char:
        case Op::checked_find_char:
        case Op::checked_find_last_char:
        case Op::checked_length: {
            const bool length = operation == Op::checked_length;
            const bool checked = length || operation == Op::checked_find_char || operation == Op::checked_find_last_char;
            const bool last = operation == Op::find_last_char || operation == Op::checked_find_last_char;
            const auto size = length ? second : count;
            const auto sought = static_cast<std::uint8_t>(second);
            Address found = 0;
            for (std::uint64_t i = 0;; ++i) {
                if (checked && i >= size)
                    fail(Fault::invalid_call, "Bionic fortify: string read exceeds supplied object size");
                const auto byte = read_byte(memory_, first, i);
                if (!length && byte == sought) { found = first + i; if (!last) break; }
                if (!byte) { if (length) found = i; break; }
            }
            r[0] = found;
            return Fault::none;
        }
        case Op::find_text: {
            const auto needle = string(memory_, second);
            r[0] = search(memory_, first, 0, needle, true);
            return Fault::none;
        }
        case Op::find_byte: {
            bounded(count);
            Address result = 0;
            for (std::uint64_t i = 0; i < count; ++i) {
                if (read_byte(memory_, first, i) == static_cast<std::uint8_t>(second)) { result = first + i; break; }
            }
            r[0] = result;
            return Fault::none;
        }
        case Op::find_bytes: {
            // memmem(haystack, haystack_size, needle, needle_size).
            if (!r[3]) { r[0] = first; return Fault::none; }
            if (r[3] > second) { r[0] = 0; return Fault::none; }
            bounded(second); bounded(r[3]);
            std::vector<std::uint8_t> needle(static_cast<std::size_t>(r[3]));
            if (!memory_.read(count, needle))
                fail(Fault::read, "native memmem needle is outside readable guest memory");
            r[0] = search(memory_, first, second, needle, false);
            return Fault::none;
        }
        case Op::copy_n:
        case Op::checked_copy_n:
        case Op::checked_copy_n_source: {
            if (operation != Op::copy_n && count > r[3])
                fail(Fault::invalid_call, "Bionic fortify: strncpy write exceeds destination object size");
            bounded(count); writable(memory_, first, count);
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (operation == Op::checked_copy_n_source && i >= r[4])
                    fail(Fault::invalid_call, "Bionic fortify: strncpy read exceeds source object size");
                const auto byte = read_byte(memory_, second, i);
                bytes[static_cast<std::size_t>(i)] = byte;
                if (!byte) break; // Value-initialized remainder is the required NUL padding.
            }
            if (count && !memory_.write(first, bytes))
                fail(Fault::write, "native strncpy destination write failed");
            // x0 already contains the destination, including zero-length copies.
            return Fault::none;
        }
        case Op::copy_sized: {
            auto bytes = string(memory_, second);
            const auto length = static_cast<std::uint64_t>(bytes.size());
            if (count) {
                const auto copied = (std::min)(length, count - 1);
                // Capacity is not the transfer size: a huge capacity may copy a short string.
                writable(memory_, first, copied + 1);
                bytes.resize(static_cast<std::size_t>(copied + 1));
                bytes[static_cast<std::size_t>(copied)] = 0;
                if (!memory_.write(first, bytes))
                    fail(Fault::write, "native strlcpy destination write failed");
            }
            r[0] = length;
            return Fault::none;
        }
        case Op::tokenize:
        case Op::tokenize_reentrant: {
            const bool reentrant=operation==Op::tokenize_reentrant;
            Address start=first;
            if(!start){
                if(reentrant){
                    std::array<std::uint8_t,8> saved{};
                    if(!memory_.read(r[2],saved))fail(Fault::read,"native strtok_r save pointer is unreadable");
                    for(unsigned i=0;i<8;++i)start|=std::uint64_t{saved[i]}<<(8*i);
                }else start=token_next_;
                if(!start){r[0]=0;return Fault::none;}
            }
            // Snapshot the delimiter set before modifying either guest object.
            const auto delimiters=string(memory_,second);
            std::array<bool,256> separator{};
            for(const auto c:delimiters)separator[c]=true;
            std::uint64_t at=0;
            auto c=read_byte(memory_,start,at);
            while(c && separator[c])c=read_byte(memory_,start,++at);
            const Address token=c?start+at:0;
            while(c && !separator[c])c=read_byte(memory_,start,++at);
            const Address cut=c?start+at:0,next=c?start+at+1:0;
            // Both writes are preflighted; no task execution or host calls intervene.
            if(reentrant)writable(memory_,r[2],8);
            if(cut)writable(memory_,cut,1);
            if(cut){const std::array<std::uint8_t,1> zero{};if(!memory_.write(cut,zero))fail(Fault::write,"native strtok delimiter write failed");}
            if(reentrant){
                std::array<std::uint8_t,8> saved{};for(unsigned i=0;i<8;++i)saved[i]=static_cast<std::uint8_t>(next>>(8*i));
                if(!memory_.write(r[2],saved))fail(Fault::write,"native strtok_r continuation write failed");
            }else token_next_=next;
            r[0]=token;return Fault::none;
        }
        case Op::checked_move:
        case Op::checked_copy:
        case Op::checked_copy_end: {
            if (count > r[3]) fail(Fault::invalid_call, operation==Op::checked_move?"Bionic fortify: memmove write exceeds destination object size":operation==Op::checked_copy?"Bionic fortify: memcpy write exceeds destination object size":"Bionic fortify: mempcpy write exceeds destination object size");
            bounded(count); writable(memory_, first, count);
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(count));
            if (count && !memory_.read(second, bytes))
                fail(Fault::read, operation==Op::checked_move?"native memmove source is outside readable guest memory":"native checked copy source is outside readable guest memory");
            if (count && !memory_.write(first, bytes))
                fail(Fault::write, operation==Op::checked_move?"native memmove destination write failed":"native checked copy destination write failed");
            if(operation==Op::checked_copy_end)r[0]=first+count;
            return Fault::none;
        }
        case Op::checked_fill: {
            if(count>r[3])fail(Fault::invalid_call,"Bionic fortify: memset write exceeds destination object size");
            bounded(count);writable(memory_,first,count);
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(count),static_cast<std::uint8_t>(second));
            if(count && !memory_.write(first,bytes))fail(Fault::write,"native checked memset destination write failed");
            return Fault::none;
        }
        }
        fail(Fault::unsupported_service, "unknown native string/memory operation");
    } catch (const Failure &failure) {
        rejection_ = failure.reason;
        return failure.fault;
    } catch (...) {
        rejection_ = "native string/memory host allocation or internal failure";
        return Fault::unsupported_service;
    }
}
} // namespace aether::bionic

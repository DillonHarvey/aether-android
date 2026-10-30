#include "aether/apk/signature.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <bcrypt.h>
#include <cstring>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <thread>
#include <wincrypt.h>

namespace aether::apk {
namespace {
constexpr std::uint32_t v2_id = 0x7109871a, v3_id = 0xf05368c0, v31_id = 0x1b93ad61;
constexpr std::size_t max_block = 8 * 1024 * 1024, max_certificate = 64 * 1024;
[[noreturn]] void invalid(const char *message) {
    throw InspectError("AETHER_APK_SIGNATURE_INVALID", "apk-signature", message);
}
void require(bool ok, const char *message) {
    if (!ok)
        invalid(message);
}
void bounded(bool ok, const char *message) {
    if (!ok)
        throw InspectError("AETHER_APK_SIGNATURE_LIMIT", "apk-signature", message);
}
void crypto(NTSTATUS status, const char *message) {
    if (status < 0)
        throw InspectError("AETHER_APK_SIGNATURE_CRYPTO", "apk-signature", message);
}
struct Cursor {
    Bytes bytes;
    std::size_t at = 0;
    Bytes take(std::size_t count) {
        require(at <= bytes.size() && count <= bytes.size() - at, "Truncated APK signing field");
        const auto value = bytes.subspan(at, count);
        at += count;
        return value;
    }
    std::uint64_t number(std::size_t width) {
        const auto data = take(width);
        std::uint64_t value = 0;
        for (std::size_t n = 0; n < data.size(); ++n)
            value |= static_cast<std::uint64_t>(data[n]) << (n * 8);
        return value;
    }
    std::uint32_t u32() { return static_cast<std::uint32_t>(number(4)); }
    Bytes field(std::size_t maximum = max_block) {
        const auto size = u32();
        bounded(size <= maximum, "APK signing field exceeds its bound");
        return take(size);
    }
    bool empty() const { return at == bytes.size(); }
    void end() const { require(empty(), "Unexpected trailing APK signing data"); }
};
std::uint64_t number(Bytes bytes, std::size_t at, std::size_t width) {
    return Cursor{bytes, at}.number(width);
}
struct Layout {
    std::size_t central = 0, end = 0, block = 0;
    Bytes v2, v3, v31;
    bool has_v31 = false, has_block = false, has_v2 = false, has_v3 = false;
};
Layout layout(Bytes bytes) {
    require(bytes.size() >= 22, "APK ZIP end record is absent");
    std::optional<std::size_t> end;
    const auto lower = bytes.size() > 65557 ? bytes.size() - 65557 : 0;
    for (auto at = bytes.size() - 22;; --at) {
        if (number(bytes, at, 4) == 0x06054b50 && number(bytes, at + 20, 2) == bytes.size() - at - 22) {
            end = at;
            break;
        }
        if (at == lower)
            break;
    }
    require(end.has_value(), "APK ZIP end record is malformed or followed by trailing data");
    require(number(bytes, *end + 4, 2) == 0 && number(bytes, *end + 6, 2) == 0 &&
                number(bytes, *end + 8, 2) == number(bytes, *end + 10, 2),
            "Multi-disk APK signing is unsupported");
    const auto central = number(bytes, *end + 16, 4), length = number(bytes, *end + 12, 4);
    require(central != 0xffffffff && length != 0xffffffff && number(bytes, *end + 10, 2) != 0xffff &&
                !(*end >= 20 && number(bytes, *end - 20, 4) == 0x07064b50),
            "ZIP64 APK signing is unsupported");
    require(central <= *end && length == *end - central,
            "APK central directory must immediately precede the ZIP end record");
    Layout result{static_cast<std::size_t>(central), *end, static_cast<std::size_t>(central)};
    constexpr std::array<std::uint8_t, 16> magic = {'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ',
                                                    'B', 'l', 'o', 'c', 'k', ' ', '4', '2'};
    if (central < 24 ||
        !std::equal(magic.begin(), magic.end(), bytes.begin() + static_cast<std::ptrdiff_t>(central - 16)))
        return result;
    result.has_block = true;
    const auto size = number(bytes, static_cast<std::size_t>(central) - 24, 8);
    require(size >= 24 && size <= central - 8, "APK signing block length is inconsistent");
    bounded(size <= max_block, "APK signing block exceeds its bound");
    result.block = static_cast<std::size_t>(central - size - 8);
    require(number(bytes, result.block, 8) == size, "APK signing block lengths disagree");
    Cursor pairs{bytes.subspan(result.block + 8, static_cast<std::size_t>(size - 24))};
    std::set<std::uint32_t> ids;
    while (!pairs.empty()) {
        bounded(ids.size() < 64, "Too many APK signing block entries");
        const auto length64 = pairs.number(8);
        require(length64 >= 4 && length64 <= pairs.bytes.size() - pairs.at,
                "APK signing pair exceeds its block");
        Cursor pair{pairs.take(static_cast<std::size_t>(length64))};
        const auto id = pair.u32();
        require(ids.insert(id).second, "Duplicate APK signing block identity is ambiguous");
        if (id == v2_id) {
            result.has_v2 = true;
            result.v2 = pair.take(pair.bytes.size() - pair.at);
        }
        if (id == v3_id) {
            result.has_v3 = true;
            result.v3 = pair.take(pair.bytes.size() - pair.at);
        }
        if (id == v31_id) {
            result.has_v31 = true;
            result.v31 = pair.take(pair.bytes.size() - pair.at);
        }
    }
    return result;
}
struct Hash {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> object;
    ULONG length = 0;
    explicit Hash(bool wide) {
        crypto(BCryptOpenAlgorithmProvider(
                   &algorithm, wide ? BCRYPT_SHA512_ALGORITHM : BCRYPT_SHA256_ALGORITHM, nullptr, 0),
               "Cannot open APK digest provider");
        try {
            ULONG size = 0, got = 0;
            crypto(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size),
                                     sizeof(size), &got, 0),
                   "Cannot size APK digest state");
            crypto(BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length),
                                     sizeof(length), &got, 0),
                   "Cannot size APK digest output");
            object.resize(size);
            crypto(BCryptCreateHash(algorithm, &hash, object.data(), static_cast<ULONG>(object.size()),
                                    nullptr, 0, 0),
                   "Cannot create APK digest state");
        } catch (...) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
    }
    ~Hash() {
        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    Hash(const Hash &) = delete;
    void add(Bytes bytes) {
        crypto(BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0),
               "Cannot hash APK signing data");
    }
    std::vector<std::uint8_t> finish() {
        std::vector<std::uint8_t> out(length);
        crypto(BCryptFinishHash(hash, out.data(), length, 0), "Cannot finish APK signing digest");
        return out;
    }
};
std::vector<std::uint8_t> digest(Bytes data, bool wide) {
    Hash hash(wide);
    hash.add(data);
    return hash.finish();
}
std::array<std::uint8_t, 5> prefix(std::uint8_t marker, std::uint32_t value) {
    return {marker, static_cast<std::uint8_t>(value), static_cast<std::uint8_t>(value >> 8),
            static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)};
}
std::vector<std::uint8_t> content_digest(Bytes bytes, const Layout &layout, bool wide) {
    std::vector<std::uint8_t> end(bytes.begin() + static_cast<std::ptrdiff_t>(layout.end), bytes.end());
    for (unsigned n = 0; n < 4; ++n)
        end[16 + n] = static_cast<std::uint8_t>(layout.block >> (n * 8));
    const std::array<Bytes, 3> sections = {bytes.first(layout.block),
                                           bytes.subspan(layout.central, layout.end - layout.central), end};
    constexpr std::size_t chunk = 1024 * 1024;
    std::uint32_t count = 0;
    for (const auto section : sections)
        count += static_cast<std::uint32_t>((section.size() + chunk - 1) / chunk);
    std::vector<Bytes> parts;
    parts.reserve(count);
    for (const auto section : sections)
        for (std::size_t offset = 0; offset < section.size(); offset += chunk)
            parts.push_back(section.subspan(offset, (std::min)(chunk, section.size() - offset)));
    std::vector<std::vector<std::uint8_t>> digests(parts.size());
    std::atomic<std::size_t> next{0};
    const auto compute = [&] {
        for (auto index = next.fetch_add(1); index < parts.size(); index = next.fetch_add(1)) {
            Hash hash(wide);
            hash.add(prefix(0xa5, static_cast<std::uint32_t>(parts[index].size())));
            hash.add(parts[index]);
            digests[index] = hash.finish();
        }
    };
    // Small APKs avoid thread startup; large inputs use available cores without
    // allocating package-sized copies or unbounded queues.
    const auto workers = (std::min)({std::size_t(std::max(1u, std::thread::hardware_concurrency())),
                                     std::size_t(32), std::max(std::size_t(1), parts.size() / 4)});
    std::vector<std::future<void>> work;
    for (std::size_t n = 1; n < workers; ++n)
        work.push_back(std::async(std::launch::async, compute));
    compute();
    for (auto &task : work)
        task.get();
    Hash whole(wide);
    whole.add(prefix(0x5a, count));
    for (const auto &value : digests)
        whole.add(value);
    return whole.finish();
}
// Minimal definite-length DER framing; Windows decodes the bounded public key
// and certificate. Exact SPKI bytes are compared, never a publisher name.
struct Der {
    Bytes bytes;
    std::size_t at = 0;
    struct Item {
        std::uint8_t tag;
        Bytes encoded, contents;
    };
    Item next() {
        require(at < bytes.size(), "Truncated signing DER value");
        const auto start = at;
        const auto tag = bytes[at++];
        require((tag & 31) != 31 && at < bytes.size(), "Unsupported or truncated signing DER tag");
        std::size_t size = bytes[at++];
        if (size & 128) {
            const auto count = size & 127;
            size = 0;
            require(count && count <= 4 && count <= bytes.size() - at && bytes[at] != 0,
                    "Noncanonical signing DER length");
            for (std::size_t n = 0; n < count; ++n)
                size = (size << 8) | bytes[at++];
            require(size >= 128, "Noncanonical signing DER length");
        }
        require(size <= bytes.size() - at, "Signing DER length exceeds its field");
        const auto body = bytes.subspan(at, size);
        at += size;
        return {tag, bytes.subspan(start, at - start), body};
    }
    Item get(std::uint8_t tag) {
        auto item = next();
        require(item.tag == tag, "Unexpected signing DER tag");
        return item;
    }
    void end() const { require(at == bytes.size(), "Trailing signing DER data"); }
};
struct Algorithm {
    std::uint32_t id;
    const char *name;
    bool wide;
    enum Kind { pss, rsa, ec, dsa } kind;
    unsigned rank;
};
constexpr std::array<Algorithm, 7> algorithms = {{{0x101, "RSA-PSS-SHA256", false, Algorithm::pss, 3},
                                                  {0x102, "RSA-PSS-SHA512", true, Algorithm::pss, 6},
                                                  {0x103, "RSA-PKCS1-SHA256", false, Algorithm::rsa, 1},
                                                  {0x104, "RSA-PKCS1-SHA512", true, Algorithm::rsa, 4},
                                                  {0x201, "ECDSA-SHA256", false, Algorithm::ec, 2},
                                                  {0x202, "ECDSA-SHA512", true, Algorithm::ec, 5},
                                                  {0x301, "DSA-SHA256", false, Algorithm::dsa, 0}}};
Bytes dsa_integer(Der &fields) {
    auto value = fields.get(2).contents;
    require(!value.empty() && !(value.front() & 128), "DSA public integer is negative or empty");
    if (value.size() > 1 && value.front() == 0) {
        require(value[1] & 128, "DSA public integer is not canonical");
        value = value.subspan(1);
    }
    require(value.front() != 0, "DSA public integer is zero");
    return value;
}
bool less_integer(Bytes value, Bytes limit) {
    return value.size() < limit.size() ||
           (value.size() == limit.size() &&
            std::lexicographical_compare(value.begin(), value.end(), limit.begin(), limit.end()));
}
struct Key {
    CERT_PUBLIC_KEY_INFO *info = nullptr;
    BCRYPT_KEY_HANDLE handle = nullptr;
    ULONG bits = 0;
    Bytes dsa_group;
    explicit Key(Bytes encoded) {
        Der outer{encoded};
        const auto sequence = outer.get(0x30);
        outer.end();
        Der fields{sequence.contents};
        const auto identifier = fields.get(0x30);
        (void)fields.get(3);
        fields.end();
        DWORD size = 0;
        require(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, encoded.data(),
                                    static_cast<DWORD>(encoded.size()),
                                    CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, nullptr, &info,
                                    &size),
                "Invalid APK signing public key");
        try {
            require(info && info->Algorithm.pszObjId && info->PublicKey.cUnusedBits == 0,
                    "Invalid APK public-key encoding");
            const Bytes parameters(info->Algorithm.Parameters.pbData, info->Algorithm.Parameters.cbData);
            const Bytes public_bits(info->PublicKey.pbData, info->PublicKey.cbData);
            if (std::strcmp(info->Algorithm.pszObjId, szOID_RSA_RSA) == 0) {
                require(parameters.empty() ||
                            (parameters.size() == 2 && parameters[0] == 5 && parameters[1] == 0),
                        "Unsupported RSA SubjectPublicKeyInfo parameters");
                Der encoded_rsa{public_bits};
                const auto rsa = encoded_rsa.get(0x30);
                encoded_rsa.end();
                Der integers{rsa.contents};
                auto modulus = integers.get(2).contents;
                auto exponent = integers.get(2).contents;
                integers.end();
                const auto positive = [](Bytes value) {
                    require(!value.empty() && !(value.front() & 128),
                            "RSA public integer is negative or empty");
                    if (value.size() > 1 && value.front() == 0) {
                        require(value[1] & 128, "RSA public integer is not canonical");
                        value = value.subspan(1);
                    }
                    return value;
                };
                modulus = positive(modulus);
                exponent = positive(exponent);
                bounded(modulus.size() >= 128 && modulus.size() <= 2048 && !exponent.empty() &&
                            exponent.size() <= 8,
                        "RSA APK signing key exceeds supported 1024-16384-bit or exponent bounds");
            } else if (std::strcmp(info->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {
                constexpr std::array<std::uint8_t, 10> p256 = {6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7};
                constexpr std::array<std::uint8_t, 7> p384 = {6, 5, 0x2b, 0x81, 4, 0, 0x22},
                                                      p521 = {6, 5, 0x2b, 0x81, 4, 0, 0x23};
                const auto width =
                    std::equal(parameters.begin(), parameters.end(), p256.begin(), p256.end())   ? 32u
                    : std::equal(parameters.begin(), parameters.end(), p384.begin(), p384.end()) ? 48u
                    : std::equal(parameters.begin(), parameters.end(), p521.begin(), p521.end()) ? 66u
                                                                                                 : 0u;
                require(width && public_bits.size() == 1 + 2 * width && public_bits.front() == 4,
                        "APK ECDSA requires an uncompressed NIST P-256, P-384 or P-521 public key");
            } else if (std::strcmp(info->Algorithm.pszObjId, szOID_X957_DSA) == 0) {
                // DSA requires explicit canonical p/q/g parameters; no inherited
                // parameters or permissive BER integers cross the host boundary.
                Der algorithm_fields{identifier.contents};
                const auto oid = algorithm_fields.get(6).contents;
                constexpr std::array<std::uint8_t, 7> dsa_oid = {0x2a, 0x86, 0x48, 0xce, 0x38, 4, 1};
                require(std::equal(oid.begin(), oid.end(), dsa_oid.begin(), dsa_oid.end()),
                        "Noncanonical DSA public-key identifier");
                const auto encoded_parameters = algorithm_fields.get(0x30);
                algorithm_fields.end();
                require(std::equal(encoded_parameters.encoded.begin(), encoded_parameters.encoded.end(),
                                   parameters.begin(), parameters.end()),
                        "DSA public-key parameters differ from their DER encoding");
                Der domain{encoded_parameters.contents};
                const auto modulus = dsa_integer(domain);
                dsa_group = dsa_integer(domain);
                const auto generator = dsa_integer(domain);
                domain.end();
                Der public_value{public_bits};
                const auto value = dsa_integer(public_value);
                public_value.end();
                bounded(((modulus.size() == 128 && dsa_group.size() == 20) ||
                         (modulus.size() == 256 && dsa_group.size() == 32)) &&
                            (modulus.front() & 128) && (dsa_group.front() & 128),
                        "DSA APK signing supports only 1024/160-bit and 2048/256-bit p/q pairs");
                const auto greater_than_one = [](Bytes number) {
                    return number.size() > 1 || number.front() > 1;
                };
                require(less_integer(dsa_group, modulus) && greater_than_one(generator) &&
                            less_integer(generator, modulus) && greater_than_one(value) &&
                            less_integer(value, modulus),
                        "DSA public-key values are outside their domain");
                if (dsa_group.size() == 32) {
                    // Crypt32's SPKI importer does not support this host's
                    // FIPS186-3 DSA keys. Import the same validated public
                    // integers through CNG's explicit V2 public-key format.
                    // SPKI carries no generation seed/counter: mark it absent.
                    BCRYPT_DSA_KEY_BLOB_V2 header{
                        BCRYPT_DSA_PUBLIC_MAGIC_V2, 256, DSA_HASH_ALGORITHM_SHA256,
                        DSA_FIPS186_3, 32, 32, {0xff, 0xff, 0xff, 0xff}};
                    static_assert(sizeof(header) == 28);
                    std::vector<std::uint8_t> blob(sizeof(header) + 32 + 32 + 3 * 256);
                    std::memcpy(blob.data(), &header, sizeof(header));
                    std::size_t offset = sizeof(header) + 32;
                    const auto append = [&](Bytes integer, std::size_t width) {
                        std::copy(integer.begin(), integer.end(),
                                  blob.begin() + static_cast<std::ptrdiff_t>(offset + width - integer.size()));
                        offset += width;
                    };
                    append(dsa_group, 32);
                    append(modulus, 256);
                    append(generator, 256);
                    append(value, 256);
                    struct Provider {
                        BCRYPT_ALG_HANDLE handle = nullptr;
                        ~Provider() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
                    } provider;
                    crypto(BCryptOpenAlgorithmProvider(&provider.handle, BCRYPT_DSA_ALGORITHM,
                                                       nullptr, 0),
                           "Cannot open APK DSA verification provider");
                    require(BCryptImportKeyPair(provider.handle, nullptr, BCRYPT_DSA_PUBLIC_BLOB,
                                                &handle, blob.data(), static_cast<ULONG>(blob.size()), 0) == 0,
                            "Unsupported or invalid APK DSA public key");
                }
            } else
                invalid("Unsupported APK SubjectPublicKeyInfo algorithm");
            if (!handle)
                require(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0, nullptr, &handle),
                        "Unsupported or invalid APK public key");
            ULONG got = 0;
            crypto(BCryptGetProperty(handle, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&bits), sizeof(bits),
                                     &got, 0),
                   "Cannot inspect APK signing key size");
            require(dsa_group.empty() || bits == (dsa_group.size() == 20 ? 1024u : 2048u),
                    "Imported DSA key size differs from its canonical domain");
        } catch (...) {
            if (handle)
                BCryptDestroyKey(handle);
            LocalFree(info);
            throw;
        }
    }
    ~Key() {
        if (handle)
            BCryptDestroyKey(handle);
        LocalFree(info);
    }
    Key(const Key &) = delete;
};
std::vector<std::uint8_t> ec_signature(Bytes encoded, ULONG bits) {
    Der outer{encoded};
    const auto sequence = outer.get(0x30);
    outer.end();
    Der pair{sequence.contents};
    const auto width = (bits + 7) / 8;
    std::vector<std::uint8_t> result(width * 2);
    for (std::size_t n = 0; n < 2; ++n) {
        auto value = pair.get(2).contents;
        require(!value.empty() && !(value.front() & 128), "ECDSA signature integer is negative or empty");
        if (value.size() > 1 && value.front() == 0) {
            require((value[1] & 128) != 0, "ECDSA signature integer is not canonical");
            value = value.subspan(1);
        }
        require(value.size() <= width, "ECDSA signature integer exceeds its curve");
        std::copy(value.begin(), value.end(),
                  result.begin() + static_cast<std::ptrdiff_t>((n + 1) * width - value.size()));
    }
    pair.end();
    return result;
}
std::vector<std::uint8_t> dsa_signature(Bytes encoded, Bytes group) {
    Der outer{encoded};
    const auto sequence = outer.get(0x30);
    outer.end();
    Der pair{sequence.contents};
    const auto width = group.size();
    std::vector<std::uint8_t> result(width * 2);
    for (std::size_t n = 0; n < 2; ++n) {
        const auto value = dsa_integer(pair);
        require(less_integer(value, group), "DSA signature integer is outside its subgroup");
        std::copy(value.begin(), value.end(),
                  result.begin() + static_cast<std::ptrdiff_t>((n + 1) * width - value.size()));
    }
    pair.end();
    return result;
}
void verify(const Algorithm &algorithm, Bytes public_key, Bytes data, Bytes signature) {
    Key key(public_key);
    const auto hash = digest(data, algorithm.wide);
    const auto *name = algorithm.wide ? BCRYPT_SHA512_ALGORITHM : BCRYPT_SHA256_ALGORITHM;
    NTSTATUS result = 0;
    if (algorithm.kind == Algorithm::ec) {
        require(std::strcmp(key.info->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0 &&
                    (key.bits == 256 || key.bits == 384 || key.bits == 521),
                "APK ECDSA verification requires a supported NIST curve");
        const auto raw = ec_signature(signature, key.bits);
        result = BCryptVerifySignature(key.handle, nullptr, const_cast<PUCHAR>(hash.data()),
                                       static_cast<ULONG>(hash.size()), const_cast<PUCHAR>(raw.data()),
                                       static_cast<ULONG>(raw.size()), 0);
    } else if (algorithm.kind == Algorithm::dsa) {
        require(std::strcmp(key.info->Algorithm.pszObjId, szOID_X957_DSA) == 0 &&
                    !key.dsa_group.empty(),
                "APK DSA verification requires a supported DSA public key");
        const auto raw = dsa_signature(signature, key.dsa_group);
        // DSA uses the leftmost min(hash bits, q bits). The CNG 1024-bit
        // provider requires that truncation explicitly rather than a 32-byte hash.
        result = BCryptVerifySignature(key.handle, nullptr, const_cast<PUCHAR>(hash.data()),
                                       static_cast<ULONG>((std::min)(hash.size(), key.dsa_group.size())),
                                       const_cast<PUCHAR>(raw.data()), static_cast<ULONG>(raw.size()), 0);
    } else {
        require(std::strcmp(key.info->Algorithm.pszObjId, szOID_RSA_RSA) == 0 && key.bits >= 1024 &&
                    key.bits <= 16384 && signature.size() == (key.bits + 7) / 8,
                "APK RSA key or signature size is unsupported");
        BCRYPT_PSS_PADDING_INFO pss{name, static_cast<ULONG>(hash.size())};
        BCRYPT_PKCS1_PADDING_INFO pkcs1{name};
        result = BCryptVerifySignature(
            key.handle, algorithm.kind == Algorithm::pss ? static_cast<void *>(&pss) : &pkcs1,
            const_cast<PUCHAR>(hash.data()), static_cast<ULONG>(hash.size()),
            const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()),
            algorithm.kind == Algorithm::pss ? BCRYPT_PAD_PSS : BCRYPT_PAD_PKCS1);
    }
    require(result == 0, "APK signed-data signature verification failed");
}
Bytes certificate_key(Bytes certificate) {
    Der outer{certificate};
    const auto sequence = outer.get(0x30);
    outer.end();
    Der cert{sequence.contents};
    const auto tbs = cert.get(0x30);
    (void)cert.get(0x30);
    (void)cert.get(3);
    cert.end();
    Der fields{tbs.contents};
    if (!fields.bytes.empty() && fields.bytes.front() == 0xa0)
        (void)fields.get(0xa0);
    (void)fields.get(2); // serial
    for (unsigned n = 0; n < 4; ++n)
        (void)fields.get(0x30); // signature, issuer, validity, subject
    const auto key = fields.get(0x30).encoded;
    const auto context = CertCreateCertificateContext(X509_ASN_ENCODING, certificate.data(),
                                                      static_cast<DWORD>(certificate.size()));
    require(context != nullptr, "APK signing certificate is not a supported X.509 certificate");
    CertFreeCertificateContext(context);
    return key;
}
using Records = std::vector<std::pair<std::uint32_t, Bytes>>;
Records records(Bytes bytes) {
    Cursor sequence{bytes};
    Records result;
    std::set<std::uint32_t> ids;
    while (!sequence.empty()) {
        bounded(result.size() < 16, "Too many APK signing algorithms");
        Cursor item{sequence.field()};
        const auto id = item.u32();
        const auto value = item.field(64 * 1024);
        item.end();
        require(ids.insert(id).second, "Duplicate APK signature algorithm");
        result.emplace_back(id, value);
    }
    require(!result.empty(), "APK signer has no signature algorithms");
    return result;
}
bool rotation(Bytes bytes, const std::string &current, std::vector<std::string> &certificates) {
    Cursor proof{bytes};
    if (proof.u32() != 1)
        return false;
    Bytes previous_key;
    std::uint32_t previous_algorithm = 0;
    std::set<std::string> seen;
    while (!proof.empty()) {
        bounded(certificates.size() < 32, "Too many APK rotation certificates");
        Cursor level{proof.field()};
        const auto signed_data = level.field();
        (void)level.u32(); // Android trust flags never grant Aether permissions.
        const auto next_algorithm = level.u32();
        const auto signature = level.field(max_certificate);
        level.end();
        if (!previous_key.empty()) {
            const auto algorithm = std::find_if(algorithms.begin(), algorithms.end(),
                                                [&](const auto &a) { return a.id == previous_algorithm; });
            if (algorithm == algorithms.end())
                return false;
            verify(*algorithm, previous_key, signed_data, signature);
        } else
            require(signature.empty(), "APK rotation root has an unexpected predecessor signature");
        Cursor data{signed_data};
        const auto certificate = data.field(max_certificate);
        const auto signed_algorithm = data.u32();
        data.end();
        require(previous_key.empty() || signed_algorithm == previous_algorithm,
                "APK rotation signature algorithm does not match its predecessor");
        previous_key = certificate_key(certificate);
        const auto identity = sha256(certificate);
        require(seen.insert(identity).second, "Duplicate APK rotation certificate");
        certificates.push_back(identity);
        previous_algorithm = next_algorithm;
    }
    require(!certificates.empty() && certificates.back() == current,
            "APK rotation proof does not end at the current signing certificate");
    return true;
}
SignatureReport verify_block(Bytes bytes, const Layout &where, Bytes encoded, bool modern,
                             const std::string &scheme, std::map<bool, std::vector<std::uint8_t>> &contents) {
    SignatureReport result;
    Cursor block{encoded};
    Cursor signers{block.field()};
    block.end();
    std::set<std::string> identities;
    while (!signers.empty()) {
        bounded(result.signers.size() < 8, "Too many APK signers");
        Cursor signer{signers.field()};
        const auto signed_data = signer.field();
        const auto min_sdk = modern ? signer.u32() : 0;
        const auto max_sdk = modern ? signer.u32() : 0;
        require(!modern || (min_sdk <= max_sdk && max_sdk <= 0x7fffffff),
                "APK v3 signer SDK range is invalid");
        const auto signatures = records(signer.field());
        const auto public_key = signer.field(max_certificate);
        signer.end();
        const Algorithm *selected = nullptr;
        Bytes selected_signature;
        for (const auto &[id, signature] : signatures)
            for (const auto &known : algorithms)
                if (id == known.id && (!selected || selected->rank < known.rank)) {
                    selected = &known;
                    selected_signature = signature;
                }
        if (!selected)
            return {
                "unsupported", scheme, "APK signer has no supported RSA, ECDSA or DSA signature algorithm.", {}};
        verify(*selected, public_key, signed_data, selected_signature);
        Cursor data{signed_data};
        const auto digests = records(data.field());
        Cursor certificates{data.field()};
        if (modern) {
            const auto signed_min = data.u32(), signed_max = data.u32();
            require(signed_min == min_sdk && signed_max == max_sdk,
                    "APK v3 signed and unsigned SDK ranges disagree");
        }
        Cursor attributes{data.field()};
        if (!modern && !data.empty()) {
            // Android's v2 verifier permits opaque signed-data extensions.
            // verify() above authenticated this complete field, including this
            // remainder. It grants no extra semantics, identity or authority.
            (void)data.take(data.bytes.size() - data.at);
            result.message = " Authenticated APK v2 signed-data extension bytes were ignored; "
                             "no semantics or authority were inferred.";
        }
        data.end();
        require(digests.size() == signatures.size(),
                "APK signature algorithm list differs from signed digests");
        Bytes expected;
        for (std::size_t n = 0; n < digests.size(); ++n) {
            require(digests[n].first == signatures[n].first,
                    "APK signature algorithms were stripped, added or reordered");
            if (digests[n].first == selected->id)
                expected = digests[n].second;
        }
        if (!contents.contains(selected->wide))
            contents.emplace(selected->wide, content_digest(bytes, where, selected->wide));
        const auto &actual = contents.at(selected->wide);
        require(std::equal(expected.begin(), expected.end(), actual.begin(), actual.end()),
                "APK protected-content digest mismatch");
        ApkSigner verified;
        verified.scheme = scheme;
        verified.min_sdk = min_sdk;
        verified.max_sdk = max_sdk;
        while (!certificates.empty()) {
            bounded(verified.certificate_count < 8, "Too many APK signer certificates");
            const auto certificate = certificates.field(max_certificate);
            const auto key = certificate_key(certificate);
            if (!verified.certificate_count) {
                require(std::equal(key.begin(), key.end(), public_key.begin(), public_key.end()),
                        "APK certificate and signing public key differ");
                verified.certificate_sha256 = sha256(certificate);
                verified.public_key_sha256 = sha256(public_key);
                require(identities.insert(verified.certificate_sha256).second,
                        "Duplicate APK signer identity");
            }
            ++verified.certificate_count;
        }
        require(verified.certificate_count != 0, "APK signer certificate is missing");
        std::set<std::uint32_t> attrs;
        while (!attributes.empty()) {
            bounded(attrs.size() < 32, "Too many APK signed attributes");
            Cursor attr{attributes.field(64 * 1024)};
            const auto id = attr.u32();
            require(attrs.insert(id).second, "Duplicate APK signed attribute");
            if (!modern && id == 0xbeeff00d) {
                const auto required_scheme = attr.u32();
                attr.end();
                require(required_scheme != 3,
                        "APK signed v3 stripping-protection attribute requires the missing v3 signature");
            }
            if (modern && id == 0x3ba06f8c &&
                !rotation(attr.take(attr.bytes.size() - attr.at), verified.certificate_sha256,
                          verified.rotation_certificates))
                return {
                    "unsupported", scheme, "APK v3 rotation proof version or algorithm is unsupported.", {}};
            if (modern && id == 0x559f8b02) {
                verified.rotation_min_sdk = attr.u32();
                attr.end();
                require(where.has_v31 && scheme == "v3",
                        "APK signed rotation-min-SDK attribute requires a companion v3.1 signature");
            }
            if (modern && id == 0xc2a6b3ba)
                return {"unsupported",
                        scheme,
                        "APK development-release signing requires SDK-targeted verification.",
                        {}};
        }
        verified.algorithm = selected->name;
        result.signers.push_back(std::move(verified));
    }
    require(!result.signers.empty(), "APK signing block has no signers");
    result.status = "verified";
    result.scheme = scheme;
    return result;
}
} // namespace
SignatureReport verify_signature(Bytes bytes) {
    const auto where = layout(bytes);
    if (!where.has_v2 && !where.has_v3 && !where.has_v31)
        return {
            where.has_block ? "unsupported" : "unverified",
            where.has_block ? "unknown" : "none-or-v1",
            "No supported v2/v3 signature was found. JAR/v1 signing is not verified; publisher identity is "
            "unverified.",
            {}};
    require(!where.has_v31 || where.has_v3, "APK v3.1 signature requires its companion v3 signature");
    std::map<bool, std::vector<std::uint8_t>> contents;
    const auto modern = where.has_v3;
    const std::string scheme = where.has_v31 ? "v3.1" : modern ? "v3" : "v2";
    auto result =
        verify_block(bytes, where, modern ? where.v3 : where.v2, modern, modern ? "v3" : "v2", contents);
    result.scheme = scheme;
    if (!result.verified())
        return result;
    if (where.has_v31) {
        auto rotated = verify_block(bytes, where, where.v31, true, "v3.1", contents);
        if (!rotated.verified())
            return rotated;
        const auto unsupported = [](const char *reason) {
            return SignatureReport{"unsupported", "v3.1", reason, {}};
        };
        if (result.signers.size() != 1 || rotated.signers.size() != 1)
            return unsupported("APK v3.1 requires one authenticated signer in each companion block.");
        const auto &older = result.signers.front();
        const auto &newer = rotated.signers.front();
        if (!older.rotation_min_sdk)
            return unsupported("APK v3.1 companion lacks authenticated rotation stripping protection.");
        require(*older.rotation_min_sdk == newer.min_sdk,
                "APK v3 rotation-min-SDK attribute disagrees with its v3.1 companion");
        if (older.min_sdk > 28 || newer.min_sdk < 33 || newer.max_sdk != 0x7fffffff ||
            older.max_sdk != newer.min_sdk - 1)
            return unsupported(
                "APK v3.1 companion ranges must cover API 28 onward without gaps or overlaps.");
        const auto &lineage = newer.rotation_certificates;
        const auto ancestor = std::find(lineage.begin(), lineage.end(), older.certificate_sha256);
        if (lineage.empty() || ancestor == lineage.end() || ancestor == lineage.end() - 1)
            return unsupported(
                "APK v3.1 rotation proof must link the companion signer to a distinct current signer.");
        const auto &previous = older.rotation_certificates;
        if (!previous.empty() && (previous.size() >= lineage.size() ||
                                  !std::equal(previous.begin(), previous.end(), lineage.begin())))
            return unsupported(
                "APK v3.1 rotation proof must preserve its companion's authenticated lineage.");
        result.signers.push_back(std::move(rotated.signers.front()));
        result.message =
            "Both APK v3/v3.1 signatures, content digests, SDK coverage and linked rotation "
            "proof are valid. The complete two-certificate identity is retained without SDK "
            "selection. Publisher identity, compatibility and execution permission are not established.";
        return result;
    }
    // Aether has no Android platform SDK identity. Accept only one signer whose
    // authenticated range covers every stable v3 platform (API 28 onward).
    // Never choose a certificate using the APK's untrusted targetSdkVersion.
    if (modern && (result.signers.size() != 1 || result.signers.front().min_sdk > 28 ||
                   result.signers.front().max_sdk != 0x7fffffff))
        return {
            "unsupported",
            scheme,
            "APK v3 requires SDK-targeted signer selection; no platform-independent identity is available.",
            {}};
    result.status = "verified";
    result.scheme = scheme;
    const auto extension_note = std::move(result.message);
    result.message = "APK " + scheme +
                     " signatures and protected content digests are valid for all reported signers. "
                     "Publisher identity, compatibility and execution permission are not established.";
    result.message += extension_note;
    return result;
}
} // namespace aether::apk

#include "aether/install/faults.hpp"
#include "aether/install/store.hpp"
#include "aether/build_info.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/image.hpp"
#include "private.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <sstream>

namespace aether::install {
namespace {
constexpr std::size_t history_limit = 16 * 1024 * 1024;
constexpr std::size_t text_limit = 16 * 1024, chain_limit = 64 * 1024, cause_limit = 16;
constexpr std::size_t record_limit = 80 * 1024, header_size = 80;
constexpr std::string_view magic = "AETFLT01";
void require(bool value, const char *code, const char *message) {
    if (!value) throw InstallError(code, message);
}
void corrupt(bool value) {
    require(value, "AETHER_FAULT_HISTORY_CORRUPT", "Fault history has an invalid record; existing evidence was kept");
}
bool missing(const std::filesystem::path &path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
    const auto error = GetLastError();
    require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND,
            "AETHER_FAULT_HISTORY_READ", "Cannot inspect retained fault history");
    return true;
}
std::vector<host::UniqueHandle> hold_paths(const std::filesystem::path &store, std::string_view app_id) {
    require(valid_app_id(app_id) && store.is_absolute() && store == store.lexically_normal(),
            "AETHER_FAULT_HISTORY_PATH", "Fault storage needs a valid app and absolute store path");
    std::vector<host::UniqueHandle> result;
    auto path = store.root_path();
    for (const auto &part : store.relative_path()) {
        path /= part;
        result.push_back(detail::hold_directory(path, false, path == store));
    }
    result.push_back(detail::hold_directory(store / utf16(app_id), false, true));
    return result;
}
// Repair only malformed encoding; preserve valid diagnostic bytes and replace
// non-display control characters. This does not interpret guest text.
std::string repaired_utf8(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (std::size_t at = 0; at < input.size();) {
        const auto first = static_cast<unsigned char>(input[at]);
        std::size_t count = first < 0x80 ? 1 : first >= 0xc2 && first <= 0xdf ? 2
                                             : first >= 0xe0 && first <= 0xef ? 3
                                             : first >= 0xf0 && first <= 0xf4 ? 4 : 0;
        bool valid = count && count <= input.size() - at;
        for (std::size_t index = 1; valid && index < count; ++index)
            valid = (static_cast<unsigned char>(input[at + index]) & 0xc0) == 0x80;
        if (valid && count >= 3) {
            const auto second = static_cast<unsigned char>(input[at + 1]);
            valid = !(first == 0xe0 && second < 0xa0) && !(first == 0xed && second >= 0xa0) &&
                    !(first == 0xf0 && second < 0x90) && !(first == 0xf4 && second >= 0x90);
        }
        if (!valid) { out += "\xef\xbf\xbd"; ++at; continue; }
        if (count == 1 && ((first < 0x20 && first != '\n' && first != '\t') || first == 0x7f))
            out += ' ';
        else
            out.append(input.substr(at, count));
        at += count;
    }
    return out;
}
std::string lower_ascii(std::string_view value) {
    std::string result(value);
    for (auto &c : result) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return result;
}
std::string redact(std::string text) {
    // Do not read environment variables, user files or credentials to scrub.
    // Recognize ordinary Windows profile spelling directly in the diagnostic.
    for (std::size_t at = 0;;) {
        const auto lower = lower_ascii(text);
        const auto pos = lower.find("\\users\\", at);
        if (pos == std::string::npos) break;
        const auto begin = pos + 7;
        auto end = text.find_first_of("\\/ \t\r\n\"'", begin);
        if (end == std::string::npos) end = text.size();
        text.replace(begin, end - begin, "[user]");
        at = begin + 6;
    }
    for (std::size_t at = 0;;) {
        const auto scheme = text.find("://", at);
        if (scheme == std::string::npos) break;
        const auto begin = scheme + 3;
        auto end = text.find_first_of(" \t\r\n\"'<>\n", begin);
        if (end == std::string::npos) end = text.size();
        auto token = text.substr(begin, end - begin);
        const auto authority_end = token.find_first_of("/?#");
        const auto credentials = token.find('@');
        if (credentials != std::string::npos &&
            (authority_end == std::string::npos || credentials < authority_end))
            token.replace(0, credentials + 1, "[credentials]@");
        const auto query = token.find_first_of("?#");
        if (query != std::string::npos) token.replace(query, token.size() - query, "?[redacted]");
        text.replace(begin, end - begin, token);
        at = begin + token.size();
    }
    // Scrub recognizable assigned credential fields without removing ordinary
    // technical references to tokens/authorization that have no assigned value.
    constexpr std::array<std::string_view, 9> sensitive = {
        "authorization", "access_token", "refresh_token", "password", "passwd",
        "api_key", "secret", "token", "apikey"};
    const auto word = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    };
    for (const auto key : sensitive) {
        for (std::size_t at = 0;;) {
            const auto lower = lower_ascii(text);
            const auto start = lower.find(key, at);
            if (start == std::string::npos) break;
            at = start + key.size();
            if ((start && word(lower[start - 1])) || (at < lower.size() && word(lower[at]))) continue;
            auto value = at;
            if (value < text.size() && (text[value] == '\"' || text[value] == '\'')) ++value;
            while (value < text.size() && (text[value] == ' ' || text[value] == '\t')) ++value;
            if (value == text.size() || (text[value] != '=' && text[value] != ':')) continue;
            ++value;
            while (value < text.size() && (text[value] == ' ' || text[value] == '\t')) ++value;
            if (value == text.size()) continue;
            std::size_t end = value;
            if (text[value] == '\"' || text[value] == '\'') {
                const auto quote = text[value++];
                end = value;
                while (end < text.size()) {
                    if (text[end] == '\\' && end + 1 < text.size()) { end += 2; continue; }
                    if (text[end] == quote) break;
                    ++end;
                }
            } else {
                const auto delimiters = key == "authorization" ? "\r\n,;}" : " \t\r\n,;}\"'";
                end = text.find_first_of(delimiters, value);
                if (end == std::string::npos) end = text.size();
            }
            if (end == value) continue;
            text.replace(value, end - value, "[redacted]");
            at = value + 10;
        }
    }
    return text;
}
std::string bounded(std::string_view value, std::size_t maximum, bool &truncated) {
    for (const auto marker : {"[middle omitted]", "[exception text truncated]",
                              "[exception chain text truncated]", "[exception chain depth limit]"})
        if (value.find(marker) != std::string_view::npos) truncated = true;
    // Bound the input before allocating encoding repair/redaction buffers.
    auto count = std::min(value.size(), maximum);
    if (count != value.size()) truncated = true;
    auto result = redact(repaired_utf8(value.substr(0, count)));
    if (result.size() > maximum) {
        count = maximum;
        while (count && (static_cast<unsigned char>(result[count]) & 0xc0) == 0x80) --count;
        result.resize(count);
        truncated = true;
    }
    return result;
}
std::string code_for(const std::exception &error) {
    if (const auto *value = dynamic_cast<const InstallError *>(&error)) return value->code;
    if (const auto *value = dynamic_cast<const apk::InspectError *>(&error)) return value->diagnostic.code;
    if (const auto *value = dynamic_cast<const dex::DexError *>(&error)) return value->code;
    const std::string_view message(error.what());
    const auto start = message.find("AETHER_");
    if (start != std::string_view::npos) {
        auto end = start;
        while (end < message.size() && end - start < 128 &&
               ((message[end] >= 'A' && message[end] <= 'Z') ||
                (message[end] >= '0' && message[end] <= '9') || message[end] == '_')) ++end;
        return std::string(message.substr(start, end - start));
    }
    return "AETHER_EXCEPTION";
}
void number(std::vector<std::uint8_t> &bytes, std::uint64_t value) {
    for (unsigned index = 0; index != 8; ++index) bytes.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
}
std::uint64_t number(apk::Bytes bytes, std::size_t &at) {
    corrupt(at <= bytes.size() && bytes.size() - at >= 8);
    std::uint64_t value = 0;
    for (unsigned index = 0; index != 8; ++index) value |= static_cast<std::uint64_t>(bytes[at++]) << (index * 8);
    return value;
}
void text(std::vector<std::uint8_t> &bytes, std::string_view value) {
    number(bytes, value.size());
    bytes.insert(bytes.end(), value.begin(), value.end());
}
std::string text(apk::Bytes bytes, std::size_t &at, std::size_t maximum) {
    const auto count = number(bytes, at);
    corrupt(count <= maximum && at <= bytes.size() && count <= bytes.size() - at);
    std::string value(reinterpret_cast<const char *>(bytes.data() + at), static_cast<std::size_t>(count));
    at += static_cast<std::size_t>(count);
    try { (void)utf16(value); } catch (const std::exception &) { corrupt(false); }
    return value;
}
std::vector<std::uint8_t> encode(const DiagnosticFault &fault) {
    require(fault.causes.size() <= cause_limit && fault.message.size() <= text_limit,
            "AETHER_FAULT_RECORD_LIMIT", "Fault record exceeds the diagnostic capture bounds");
    std::vector<std::uint8_t> bytes;
    number(bytes, fault.utc_100ns); number(bytes, fault.package_generation); number(bytes, fault.message_truncated);
    for (const auto *value : {&fault.stage, &fault.code, &fault.package_sha256, &fault.aether_version,
                              &fault.aether_configuration}) {
        require(value->size() <= 512, "AETHER_FAULT_RECORD_LIMIT", "Fault metadata exceeds its bound");
        (void)json_quote(*value);
        text(bytes, *value);
    }
    (void)json_quote(fault.message); text(bytes, fault.message); number(bytes, fault.causes.size());
    std::size_t total = fault.message.size();
    for (const auto &cause : fault.causes) {
        require(cause.size() <= text_limit && total <= chain_limit - cause.size(),
                "AETHER_FAULT_RECORD_LIMIT", "Fault cause chain exceeds its bound");
        total += cause.size(); (void)json_quote(cause); text(bytes, cause);
    }
    require(bytes.size() <= record_limit, "AETHER_FAULT_RECORD_LIMIT", "Fault record exceeds its storage bound");
    return bytes;
}
DiagnosticFault decode(apk::Bytes bytes) {
    DiagnosticFault fault;
    std::size_t at = 0;
    fault.utc_100ns = number(bytes, at); fault.package_generation = number(bytes, at);
    const auto truncated = number(bytes, at); corrupt(truncated <= 1); fault.message_truncated = truncated != 0;
    fault.stage = text(bytes, at, 512); fault.code = text(bytes, at, 512);
    fault.package_sha256 = text(bytes, at, 512); fault.aether_version = text(bytes, at, 512);
    fault.aether_configuration = text(bytes, at, 512); fault.message = text(bytes, at, text_limit);
    const auto causes = number(bytes, at); corrupt(causes <= cause_limit);
    std::size_t total = fault.message.size();
    for (std::uint64_t index = 0; index < causes; ++index) {
        auto cause = text(bytes, at, text_limit); corrupt(total <= chain_limit - cause.size());
        total += cause.size(); fault.causes.push_back(std::move(cause));
    }
    corrupt(at == bytes.size() && fault.utc_100ns != 0);
    return fault;
}
void parse(apk::Bytes bytes, FaultHistory &history) {
    std::size_t at = 0;
    while (at != bytes.size()) {
        require(bytes.size() - at >= header_size, "AETHER_FAULT_HISTORY_PARTIAL",
                "Fault history ends in a partial record; existing evidence was kept");
        const auto header = bytes.subspan(at, header_size);
        corrupt(std::equal(magic.begin(), magic.end(), header.begin()));
        std::size_t count_at = 8;
        const auto count = number(header, count_at);
        corrupt(count && count <= record_limit);
        require(count <= bytes.size() - at - header_size, "AETHER_FAULT_HISTORY_PARTIAL",
                "Fault history ends in a partial record; existing evidence was kept");
        const auto payload = bytes.subspan(at + header_size, static_cast<std::size_t>(count));
        const std::string digest(reinterpret_cast<const char *>(header.data() + 16), 64);
        corrupt(apk::sha256(payload) == digest);
        history.entries.push_back(decode(payload));
        at += header_size + static_cast<std::size_t>(count);
    }
}
} // namespace

DiagnosticFault capture_fault(std::exception_ptr error, std::string_view stage,
                              std::string_view package_sha256, std::uint64_t generation) {
    DiagnosticFault fault;
    fault.stage = bounded(stage, 512, fault.message_truncated);
    fault.package_sha256 = bounded(package_sha256, 512, fault.message_truncated);
    fault.package_generation = generation;
    fault.aether_version = std::string(build::version);
    fault.aether_configuration = std::string(build::configuration) + "; " + std::string(build::compiler) +
        "; diagnostics compiled=" __DATE__ " " __TIME__;
    FILETIME now{}; GetSystemTimePreciseAsFileTime(&now);
    fault.utc_100ns = static_cast<std::uint64_t>(now.dwHighDateTime) << 32 | now.dwLowDateTime;
    std::size_t total = 0;
    for (std::size_t depth = 0; error; ++depth) {
        if (depth > cause_limit || total == chain_limit) { fault.message_truncated = true; break; }
        std::string message;
        std::exception_ptr next;
        try { std::rethrow_exception(error); }
        catch (const std::exception &value) {
            if (depth == 0) fault.code = bounded(code_for(value), 512, fault.message_truncated);
            message = bounded(value.what(), std::min(text_limit, chain_limit - total), fault.message_truncated);
            if (const auto *nested = dynamic_cast<const std::nested_exception *>(&value)) next = nested->nested_ptr();
        } catch (...) {
            if (depth == 0) fault.code = "AETHER_NONSTANDARD_EXCEPTION";
            message = bounded("A non-standard exception was caught; no textual payload is available",
                              std::min(text_limit, chain_limit - total), fault.message_truncated);
        }
        total += message.size();
        if (depth == 0) fault.message = std::move(message); else fault.causes.push_back(std::move(message));
        error = next;
    }
    if (fault.code.empty()) { fault.code = "AETHER_FAULT_WITHOUT_EXCEPTION"; fault.message = "No exception payload was available"; }
    return fault;
}
void retain_fault(const std::filesystem::path &store, std::string_view app_id, const DiagnosticFault &fault) {
    auto held = hold_paths(store, app_id);
    const auto directory = store / utf16(app_id) / L"faults";
    held.push_back(detail::hold_directory(directory, true, true));
    auto file = detail::private_file(directory / L"history.bin", GENERIC_READ | GENERIC_WRITE,
                                      OPEN_ALWAYS, history_limit);
    auto existing = detail::read_contents(file.get());
    FaultHistory verified; parse(existing, verified); // Never append beyond damaged or partial evidence.
    const auto payload = encode(fault);
    require(payload.size() + header_size <= history_limit - existing.size(), "AETHER_FAULT_HISTORY_FULL",
            "Fault history is full; earlier faults were kept and this fault was not saved");
    std::vector<std::uint8_t> record(magic.begin(), magic.end());
    number(record, payload.size());
    const auto digest = apk::sha256(payload); record.insert(record.end(), digest.begin(), digest.end());
    record.insert(record.end(), payload.begin(), payload.end());
    LARGE_INTEGER end{};
    require(SetFilePointerEx(file.get(), end, nullptr, FILE_END) != FALSE,
            "AETHER_FAULT_HISTORY_WRITE", "Cannot seek fault history; this fault was not saved");
    DWORD written = 0;
    require(WriteFile(file.get(), record.data(), static_cast<DWORD>(record.size()), &written, nullptr) &&
                written == record.size() && FlushFileBuffers(file.get()),
            "AETHER_FAULT_HISTORY_WRITE", "Fault history write or flush failed; no retry or evidence deletion was attempted");
}
FaultHistory read_faults(const std::filesystem::path &store, std::string_view app_id) {
    FaultHistory result;
    try {
        require(valid_app_id(app_id), "AETHER_FAULT_HISTORY_PATH", "Fault history requires a valid app identity");
        if (missing(store / utf16(app_id))) return result; // Explicit delete-data removes owned history too.
        auto held = hold_paths(store, app_id);
        const auto directory = store / utf16(app_id) / L"faults";
        if (missing(directory)) return result;
        held.push_back(detail::hold_directory(directory, false, true));
        if (missing(directory / L"history.bin")) return result;
        auto file = detail::private_file(directory / L"history.bin", GENERIC_READ, OPEN_EXISTING, history_limit,
                                          FILE_SHARE_READ);
        const auto bytes = detail::read_contents(file.get());
        parse(bytes, result);
        result.status = "retained";
    } catch (const std::exception &error) {
        result.complete = false;
        result.status = result.entries.empty() ? "unavailable" : "partial";
        if (const auto *value = dynamic_cast<const InstallError *>(&error)) result.code = value->code;
        else result.code = "AETHER_FAULT_HISTORY_READ";
    }
    return result;
}
std::string fault_json(const DiagnosticFault &fault) {
    // Export copies are bounded separately from the unchanged local journal.
    // Include every cause label, sharing its text budget, so nested causes are
    // represented even when a large outer message would consume the report.
    auto shown = fault;
    bool export_truncated = false;
    const auto trim = [&export_truncated](std::string &value, std::size_t limit) {
        if (value.size() <= limit) return;
        auto end = limit;
        while (end && (static_cast<unsigned char>(value[end]) & 0xc0) == 0x80) --end;
        value.resize(end);
        export_truncated = true;
    };
    std::size_t budget = 2 * 1024;
    for (;;) {
        trim(shown.message, budget);
        const auto cause_budget = shown.causes.empty() ? 0 : budget / shown.causes.size();
        for (auto &cause : shown.causes) trim(cause, cause_budget);
        std::ostringstream out;
        out << "{\"stage\":" << json_quote(shown.stage) << ",\"code\":" << json_quote(shown.code)
            << ",\"message\":" << json_quote(shown.message) << ",\"packageSha256\":" << json_quote(shown.package_sha256)
            << ",\"packageGeneration\":" << shown.package_generation << ",\"utc100ns\":" << shown.utc_100ns
            << ",\"aetherVersion\":" << json_quote(shown.aether_version)
            << ",\"aetherConfiguration\":" << json_quote(shown.aether_configuration)
            << ",\"messageTruncated\":" << (shown.message_truncated ? "true" : "false")
            << ",\"exportTruncated\":" << (export_truncated ? "true" : "false")
            << ",\"diagnosticTextTrusted\":false,\"redaction\":\"best-effort-profile-credentials-and-URI\",\"causes\":[";
        for (std::size_t index = 0; index < shown.causes.size(); ++index)
            out << (index ? "," : "") << json_quote(shown.causes[index]);
        out << "]}";
        auto result = out.str();
        if (result.size() <= 6 * 1024) return result;
        require(budget != 0, "AETHER_FAULT_EXPORT_LIMIT", "Fault metadata exceeds the bounded export size");
        budget /= 2;
    }
}
std::string fault_history_json(const FaultHistory &history) {
    std::vector<std::string> records;
    std::size_t remaining = 23 * 1024;
    bool entry_truncated = false;
    for (auto entry = history.entries.rbegin(); entry != history.entries.rend(); ++entry) {
        auto record = fault_json(*entry);
        if (record.size() + 1 > remaining) break;
        remaining -= record.size() + 1;
        entry_truncated = entry_truncated || record.find("\"exportTruncated\":true") != std::string::npos;
        records.push_back(std::move(record));
    }
    std::ostringstream out;
    out << "{\"status\":" << json_quote(history.status) << ",\"code\":" << json_quote(history.code)
        << ",\"complete\":" << (history.complete ? "true" : "false")
        << ",\"maximumBytes\":" << history_limit << ",\"automaticDeletion\":false"
        << ",\"totalEntries\":" << history.entries.size() << ",\"exportedEntries\":" << records.size()
        << ",\"omittedEntries\":" << history.entries.size() - records.size()
        << ",\"exportTruncated\":" << (entry_truncated || records.size() != history.entries.size() ? "true" : "false")
        << ",\"entryOrder\":\"oldest-to-newest-of-newest-subset\",\"entries\":[";
    for (auto record = records.rbegin(); record != records.rend(); ++record)
        out << (record != records.rbegin() ? "," : "") << *record;
    out << "]}";
    return out.str();
}
std::string fault_history_text(const FaultHistory &history) {
    std::ostringstream out;
    out << "Retained fault history: " << history.status << ' ' << history.code
        << "; complete=" << (history.complete ? "true" : "false") << "; entries=" << history.entries.size()
        << "\nDiagnostic text is untrusted and profile/URI redaction is best effort. Review before sharing.\n";
    out << "Newest retained faults are shown first; local history is never pruned.\n";
    std::size_t shown = 0;
    for (auto fault = history.entries.rbegin(); fault != history.entries.rend(); ++fault) {
        const auto record = fault_json(*fault);
        if (static_cast<std::size_t>(out.tellp()) + record.size() + 256 > 30 * 1024) break;
        out << '\n' << record << '\n';
        ++shown;
    }
    if (shown != history.entries.size())
        out << "\n[Display/export subset: " << shown << " of " << history.entries.size()
            << " retained faults shown. Full records remain in local history.]\n";
    return out.str();
}
} // namespace aether::install

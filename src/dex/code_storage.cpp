#include "aether/dex/image.hpp"

namespace aether::dex {
CodeStorage::CodeStorage() noexcept=default;
CodeStorage::CodeStorage(std::nullopt_t) noexcept {}
CodeStorage::CodeStorage(const Code &value):value_(std::make_unique<Code>(value)) {}
CodeStorage::CodeStorage(Code &&value):value_(std::make_unique<Code>(std::move(value))) {}
CodeStorage::CodeStorage(const std::optional<Code> &value)
    :value_(value?std::make_unique<Code>(*value):nullptr) {}
CodeStorage::CodeStorage(std::optional<Code> &&value)
    :value_(value?std::make_unique<Code>(std::move(*value)):nullptr) {}
CodeStorage::CodeStorage(const CodeStorage &other)
    :value_(other.value_?std::make_unique<Code>(*other.value_):nullptr) {}
CodeStorage::CodeStorage(CodeStorage &&other) noexcept=default;
CodeStorage::~CodeStorage()=default;
CodeStorage &CodeStorage::operator=(const CodeStorage &other) {
    if(this!=&other){CodeStorage replacement(other);swap(replacement);}
    return *this;
}
CodeStorage &CodeStorage::operator=(CodeStorage &&other) noexcept {
    if(this!=&other)value_=std::move(other.value_);
    return *this;
}
CodeStorage &CodeStorage::operator=(std::nullopt_t) noexcept {
    reset();return *this;
}
CodeStorage &CodeStorage::operator=(const Code &value) {
    CodeStorage replacement(value);swap(replacement);return *this;
}
CodeStorage &CodeStorage::operator=(Code &&value) {
    CodeStorage replacement(std::move(value));swap(replacement);return *this;
}
CodeStorage::operator bool() const noexcept {return bool(value_);}
bool CodeStorage::has_value() const noexcept {return bool(value_);}
Code &CodeStorage::operator*() noexcept {return *value_;}
const Code &CodeStorage::operator*() const noexcept {return *value_;}
Code *CodeStorage::operator->() noexcept {return value_.get();}
const Code *CodeStorage::operator->() const noexcept {return value_.get();}
Code &CodeStorage::value() {
    if(!value_)throw std::bad_optional_access{};
    return *value_;
}
const Code &CodeStorage::value() const {
    if(!value_)throw std::bad_optional_access{};
    return *value_;
}
void CodeStorage::reset() noexcept {value_.reset();}
Code &CodeStorage::emplace() {
    CodeStorage replacement(Code{});swap(replacement);return *value_;
}
void CodeStorage::swap(CodeStorage &other) noexcept {value_.swap(other.value_);}
} // namespace aether::dex

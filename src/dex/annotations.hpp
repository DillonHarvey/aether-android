#pragma once
#include "aether/dex/image.hpp"

namespace aether::dex {
// Full structural validation, with only direct SYSTEM class-naming references
// retained. No annotation is evaluated or exposed as an annotation object.
// Called after inventory, identifier and class validation have populated the image.
void validate_annotations(std::span<const std::uint8_t> bytes, DexImage &image);
} // namespace aether::dex

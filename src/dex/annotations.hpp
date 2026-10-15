#pragma once
#include "aether/dex/image.hpp"

namespace aether::dex {
// Structural validation only: annotations are not exposed through reflection or executed.
// Called after inventory, identifier and class validation have populated the image.
void validate_annotations(std::span<const std::uint8_t> bytes, const DexImage &image);
} // namespace aether::dex

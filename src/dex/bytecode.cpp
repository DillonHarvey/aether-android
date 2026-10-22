#include "aether/dex/bytecode.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <set>

namespace aether::dex {
const std::array<Opcode, 256> &opcode_registry() noexcept {
    static const auto table = [] {
        std::array<Opcode, 256> t{};
        const auto one = [&](unsigned op, std::string_view name, Format format, std::uint8_t width) {
            t[op] = {name, format, width};
        };
        const auto group = [&](unsigned first, unsigned last, std::string_view name, Format format,
                               std::uint8_t width) {
            for (auto i = first; i <= last; ++i)
                one(i, name, format, width);
        };
        one(0, "nop", Format::f10x, 1);
        for (unsigned i = 1; i <= 7; i += 3) {
            one(i, "move", Format::f12x, 1);
            one(i + 1, "move/from16", Format::f22x, 2);
            one(i + 2, "move/16", Format::f32x, 3);
        }
        group(0x0a, 0x0d, "move-result/exception", Format::f11x, 1);
        one(0x0e, "return-void", Format::f10x, 1);
        group(0x0f, 0x11, "return", Format::f11x, 1);
        one(0x12, "const/4", Format::f11n, 1);
        one(0x13, "const/16", Format::f21s, 2);
        one(0x14, "const", Format::f31i, 3);
        one(0x15, "const/high16", Format::f21h, 2);
        one(0x16, "const-wide/16", Format::f21s, 2);
        one(0x17, "const-wide/32", Format::f31i, 3);
        one(0x18, "const-wide", Format::f51l, 5);
        one(0x19, "const-wide/high16", Format::f21h, 2);
        one(0x1a, "const-string", Format::f21c, 2);
        one(0x1b, "const-string/jumbo", Format::f31c, 3);
        one(0x1c, "const-class", Format::f21c, 2);
        one(0x1d, "monitor-enter", Format::f11x, 1);
        one(0x1e, "monitor-exit", Format::f11x, 1);
        one(0x1f, "check-cast", Format::f21c, 2);
        one(0x20, "instance-of", Format::f22c, 2);
        one(0x21, "array-length", Format::f12x, 1);
        one(0x22, "new-instance", Format::f21c, 2);
        one(0x23, "new-array", Format::f22c, 2);
        one(0x24, "filled-new-array", Format::f35c, 3);
        one(0x25, "filled-new-array/range", Format::f3rc, 3);
        one(0x27, "throw", Format::f11x, 1);
        one(0x28, "goto", Format::f10t, 1);
        one(0x29, "goto/16", Format::f20t, 2);
        one(0x2a, "goto/32", Format::f30t, 3);
        one(0x2b, "packed-switch", Format::f31t, 3);
        one(0x2c, "sparse-switch", Format::f31t, 3);
        group(0x2d, 0x31, "compare", Format::f23x, 2);
        group(0x32, 0x37, "if", Format::f22t, 2);
        group(0x38, 0x3d, "if-zero", Format::f21t, 2);
        group(0x44, 0x51, "array-access", Format::f23x, 2);
        group(0x52, 0x5f, "instance-field", Format::f22c, 2);
        group(0x60, 0x6d, "static-field", Format::f21c, 2);
        one(0x6e, "invoke-virtual", Format::f35c, 3);
        one(0x6f, "invoke-super", Format::f35c, 3);
        one(0x70, "invoke-direct", Format::f35c, 3);
        one(0x71, "invoke-static", Format::f35c, 3);
        one(0x72, "invoke-interface", Format::f35c, 3);
        one(0x74, "invoke-virtual/range", Format::f3rc, 3);
        one(0x75, "invoke-super/range", Format::f3rc, 3);
        one(0x76, "invoke-direct/range", Format::f3rc, 3);
        one(0x77, "invoke-static/range", Format::f3rc, 3);
        one(0x78, "invoke-interface/range", Format::f3rc, 3);
        one(0x81, "int-to-long", Format::f12x, 1);
        one(0x82, "int-to-float", Format::f12x, 1);
        one(0x84, "long-to-int", Format::f12x, 1);
        one(0x87, "float-to-int", Format::f12x, 1);
        one(0x8d, "int-to-byte", Format::f12x, 1);
        one(0x8e, "int-to-char", Format::f12x, 1);
        one(0x8f, "int-to-short", Format::f12x, 1);
        group(0x90, 0xaf, "binary", Format::f23x, 2);
        group(0xb0, 0xcf, "binary/2addr", Format::f12x, 1);
        group(0xd0, 0xd7, "binary/lit16", Format::f22s, 2);
        group(0xd8, 0xe2, "binary/lit8", Format::f22b, 2);
        return t;
    }();
    return table;
}
namespace {
[[noreturn]] void invalid(Index method, std::uint32_t pc, const std::string &message,
                          std::string_view kind = "VERIFY") {
    throw DexError("AETHER_DEX_" + std::string(kind),
                   "method@" + std::to_string(method) + " pc=" + std::to_string(pc) + ": " + message);
}
bool invoke(unsigned op) { return (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78); }
bool wide_binary(unsigned op) { return (op >= 0x9b && op <= 0xa5) || (op >= 0xab && op <= 0xaf); }
unsigned value_category(std::string_view type) {
    return reference_type(type) ? 2 : (type_words(type) == 2 ? 1 : 0);
}
} // namespace
VerifiedCode verify(const DexImage &image, Index method_index) {
    if (method_index >= image.methods.size() || !image.methods[method_index].code)
        invalid(method_index, 0, "Method has no executable code item");
    const auto &method = image.methods[method_index];
    const auto &code = *method.code;
    const auto &units = code.units;
    if (units.empty() || units.size() > 65536 || code.registers > 256 || code.incoming > code.registers)
        invalid(method_index, 0, "Invalid code limits");
    VerifiedCode result;
    result.at.resize(units.size(), no_index);
    std::vector<std::uint32_t> data_width(units.size()), data_prefix(units.size() + 1);
    const auto signed32 = [&](std::uint32_t at) {
        return std::bit_cast<std::int32_t>(std::uint32_t(units[at]) | (std::uint32_t(units[at + 1]) << 16));
    };
    const auto reg = [&](std::uint32_t pc, std::uint32_t r, unsigned width = 1) {
        if (r >= code.registers || width > code.registers - r)
            invalid(method_index, pc, "Register exceeds frame (v" + std::to_string(r) + ")");
    };
    for (std::uint32_t pc = 0; pc < units.size();) {
        const auto first = units[pc];
        if (!first && (pc & 1) && pc + 1 < units.size() &&
            (units[pc + 1] == 0x0100 || units[pc + 1] == 0x0200)) {
            // D8 aligns non-executable payloads with an unreachable nop.
            data_width[pc] = data_prefix[pc + 1] = 1;
            ++pc;
            continue;
        }
        if (first == 0x0100) {
            if ((pc & 1) || units.size() - pc < 4)
                invalid(method_index, pc, "Misaligned or truncated packed-switch payload");
            const auto count = std::uint32_t(units[pc + 1]), width = 4 + count * 2;
            if (width > units.size() - pc)
                invalid(method_index, pc, "Truncated packed-switch targets");
            if (count &&
                std::int64_t(signed32(pc + 2)) + count - 1 > std::numeric_limits<std::int32_t>::max())
                invalid(method_index, pc, "Packed-switch key range overflows int32");
            data_width[pc] = width;
            std::fill(data_prefix.begin() + pc + 1, data_prefix.begin() + pc + width + 1, 1);
            pc += width;
            continue;
        }
        if (first == 0x0200) {
            if ((pc & 1) || units.size() - pc < 2)
                invalid(method_index, pc, "Misaligned or truncated sparse-switch payload");
            const auto count = std::uint32_t(units[pc + 1]), width = 2 + count * 4;
            if (width > units.size() - pc)
                invalid(method_index, pc, "Truncated sparse-switch keys or targets");
            for (std::uint32_t n = 1; n < count; ++n)
                if (signed32(pc + 2 + (n - 1) * 2) >= signed32(pc + 2 + n * 2))
                    invalid(method_index, pc, "Sparse-switch keys must be strictly increasing");
            data_width[pc] = width;
            std::fill(data_prefix.begin() + pc + 1, data_prefix.begin() + pc + width + 1, 1);
            pc += width;
            continue;
        }
        const auto op = static_cast<std::uint8_t>(first);
        const auto &entry = opcode_registry()[op];
        if (!entry.width)
            invalid(method_index, pc, "Unsupported opcode " + std::to_string(op), "OPCODE_UNSUPPORTED");
        if (entry.width > units.size() - pc)
            invalid(method_index, pc, "Truncated instruction");
        Instruction ins;
        ins.pc = pc;
        ins.next = pc + entry.width;
        ins.opcode = op;
        const auto u1 = entry.width > 1 ? units[pc + 1] : std::uint16_t{};
        const auto u2 = entry.width > 2 ? units[pc + 2] : std::uint16_t{};
        const auto bits32 = std::uint32_t(u1) | (std::uint32_t(u2) << 16);
        ins.a = first >> 8;
        switch (entry.format) {
        case Format::f10x:
            if (ins.a)
                invalid(method_index, pc, "Reserved bits/payload not supported");
            break;
        case Format::f12x:
            ins.a &= 15;
            ins.b = first >> 12;
            break;
        case Format::f22x:
            ins.b = u1;
            break;
        case Format::f32x:
            if (ins.a)
                invalid(method_index, pc, "Reserved instruction bits");
            ins.a = u1;
            ins.b = u2;
            break;
        case Format::f11x:
            break;
        case Format::f11n:
            ins.a &= 15;
            ins.literal = static_cast<std::uint64_t>(static_cast<std::int64_t>(first >> 12) -
                                                     ((first & 0x8000) ? 16 : 0));
            break;
        case Format::f21s:
            ins.literal =
                static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(u1)));
            break;
        case Format::f31i:
            ins.literal =
                static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(bits32)));
            break;
        case Format::f21h:
            ins.literal = std::uint64_t(u1) << (op == 0x19 ? 48 : 16);
            break;
        case Format::f51l:
            ins.literal =
                bits32 | (std::uint64_t(units[pc + 3]) << 32) | (std::uint64_t(units[pc + 4]) << 48);
            break;
        case Format::f21c:
            ins.index = u1;
            break;
        case Format::f31c:
            ins.index = bits32;
            break;
        case Format::f22c:
            ins.a &= 15;
            ins.b = first >> 12;
            ins.index = u1;
            break;
        case Format::f23x:
            ins.b = u1 & 255;
            ins.c = u1 >> 8;
            break;
        case Format::f35c: {
            ins.index = u1;
            const auto count = unsigned(first >> 12);
            if (count > 5)
                invalid(method_index, pc, "Invoke has more than five encoded registers");
            for (unsigned i = 0; i < count; ++i)
                ins.arguments.push_back(
                    static_cast<std::uint16_t>(i == 4 ? (first >> 8) & 15 : (u2 >> (i * 4)) & 15));
            break;
        }
        case Format::f3rc:
            ins.index = u1;
            for (unsigned i = 0; i < ins.a; ++i) {
                if (std::uint32_t(u2) + i > 65535)
                    invalid(method_index, pc, "Range register overflow");
                ins.arguments.push_back(static_cast<std::uint16_t>(u2 + i));
            }
            break;
        case Format::f10t:
            ins.branch = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(ins.a));
            break;
        case Format::f20t:
            if (ins.a)
                invalid(method_index, pc, "Reserved branch bits");
            ins.branch = std::bit_cast<std::int16_t>(u1);
            break;
        case Format::f30t:
            if (ins.a)
                invalid(method_index, pc, "Reserved branch bits");
            ins.branch = std::bit_cast<std::int32_t>(bits32);
            break;
        case Format::f31t:
            ins.branch = std::bit_cast<std::int32_t>(bits32);
            break;
        case Format::f22t:
            ins.a &= 15;
            ins.b = first >> 12;
            ins.branch = std::bit_cast<std::int16_t>(u1);
            break;
        case Format::f21t:
            ins.branch = std::bit_cast<std::int16_t>(u1);
            break;
        case Format::f22s:
            ins.a &= 15;
            ins.b = first >> 12;
            ins.literal =
                static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(u1)));
            break;
        case Format::f22b:
            ins.b = u1 & 255;
            ins.literal = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(u1 >> 8))));
            break;
        default:
            invalid(method_index, pc, "Unimplemented instruction format");
        }
        if (code.references) {
            const auto &map = *code.references;
            const std::vector<Index> *indices = nullptr;
            if (op == 0x1a || op == 0x1b)
                indices = &map.strings;
            else if (op == 0x1c || (op >= 0x1f && op <= 0x20) || (op >= 0x22 && op <= 0x25))
                indices = &map.types;
            else if (op >= 0x52 && op <= 0x6d)
                indices = &map.fields;
            else if (invoke(op))
                indices = &map.methods;
            if (indices) {
                if (ins.index >= indices->size())
                    invalid(method_index, pc, "File-local operand exceeds " + map.source);
                ins.index = (*indices)[ins.index];
            }
        }
        if (op >= 1 && op <= 9) {
            const auto width = op >= 4 && op <= 6 ? 2u : 1u;
            reg(pc, ins.a, width);
            reg(pc, ins.b, width);
        } else if (op >= 0x0a && op <= 0x1f && op != 0x0e) {
            reg(pc, ins.a, op == 0x0b || op == 0x10 || (op >= 0x16 && op <= 0x19) ? 2 : 1);
        } else if (op == 0x20 || op == 0x21 || op == 0x23) {
            reg(pc, ins.a);
            reg(pc, ins.b);
        } else if (op == 0x22 || op == 0x27 || op == 0x2b || op == 0x2c || (op >= 0x38 && op <= 0x3d)) {
            reg(pc, ins.a);
        } else if (op >= 0x2d && op <= 0x31) {
            reg(pc, ins.a);
            reg(pc, ins.b, op >= 0x2f ? 2 : 1);
            reg(pc, ins.c, op >= 0x2f ? 2 : 1);
        } else if (op >= 0x32 && op <= 0x37) {
            reg(pc, ins.a);
            reg(pc, ins.b);
        } else if (op >= 0x44 && op <= 0x51) {
            reg(pc, ins.a, (op - 0x44) % 7 == 1 ? 2 : 1);
            reg(pc, ins.b);
            reg(pc, ins.c);
        } else if (op >= 0x52 && op <= 0x6d) {
            reg(pc, ins.a, (op - 0x52) % 7 == 1 ? 2 : 1);
            if (op < 0x60)
                reg(pc, ins.b);
        } else if (op == 0x81 || op == 0x82 || op == 0x84 || op == 0x87 || (op >= 0x8d && op <= 0x8f)) {
            reg(pc, ins.a, op == 0x81 ? 2 : 1);
            reg(pc, ins.b, op == 0x84 ? 2 : 1);
        } else if (op >= 0x90 && op <= 0xcf) {
            const auto binary = op >= 0xb0 ? op - 0x20u : op;
            const auto width = wide_binary(binary) ? 2u : 1u;
            reg(pc, ins.a, width);
            reg(pc, ins.b, op >= 0xb0 && binary >= 0xa3 && binary <= 0xa5 ? 1 : width);
            if (op < 0xb0)
                reg(pc, ins.c, binary >= 0xa3 && binary <= 0xa5 ? 1 : width);
        } else if (op >= 0xd0 && op <= 0xe2) {
            reg(pc, ins.a);
            reg(pc, ins.b);
        }
        for (const auto arg : ins.arguments)
            reg(pc, arg);
        if ((op == 0x1a || op == 0x1b) && ins.index >= image.strings.size())
            invalid(method_index, pc, "Invalid string index");
        if ((op == 0x1c || (op >= 0x1f && op <= 0x20) || (op >= 0x22 && op <= 0x25)) &&
            ins.index >= image.types.size())
            invalid(method_index, pc, "Invalid type index");
        if (op == 0x22 && image.types[ins.index].front() != 'L')
            invalid(method_index, pc, "new-instance requires a non-array class type");
        if (op == 0x23 && image.types[ins.index].front() != '[')
            invalid(method_index, pc, "new-array requires an array type");
        if (op >= 0x52 && op <= 0x6d) {
            if (ins.index >= image.fields.size())
                invalid(method_index, pc, "Invalid field index");
            const auto &field = image.fields[ins.index];
            const auto &type = image.types[field.type];
            const auto category = unsigned(op - 0x52) % 7;
            const auto expected = value_category(type);
            if ((category == 0 && type != "I" && type != "F") || (category < 3 && category != expected) ||
                (category == 3 && type != "Z") || (category == 4 && type != "B") ||
                (category == 5 && type != "C") || (category == 6 && type != "S"))
                invalid(method_index, pc, "Field opcode does not match field type");
            if (field.declared && ((field.flags & 8) != 0) != (op >= 0x60))
                invalid(method_index, pc, "Field static/instance mismatch");
        }
        if (invoke(op)) {
            if (ins.index >= image.methods.size())
                invalid(method_index, pc, "Invalid method index");
            const auto &target = image.methods[ins.index];
            const auto &proto = image.prototypes[target.prototype];
            const auto stat = op == 0x71 || op == 0x77;
            if (target.declared && bool(target.flags & 8) != stat)
                invalid(method_index, pc, "Method static/instance mismatch");
            if (ins.arguments.size() != proto.argument_words + (stat ? 0 : 1) ||
                ins.arguments.size() > code.outgoing)
                invalid(method_index, pc, "Invocation word count/outgoing frame mismatch");
            std::size_t n = stat ? 0 : 1;
            for (const auto type : proto.parameters) {
                if (type_words(image.types[type]) == 2) {
                    if (ins.arguments[n] + 1 != ins.arguments[n + 1])
                        invalid(method_index, pc, "Nonadjacent wide argument registers");
                    n += 2;
                } else
                    ++n;
            }
        }
        if (op == 0x24 || op == 0x25) {
            const auto &type = image.types[ins.index];
            if (type.size() < 2 || type[0] != '[' || type_words(std::string_view(type).substr(1)) == 2)
                invalid(method_index, pc, "filled-new-array requires one-word elements");
            // outs_size describes method calls, not array elements. Their
            // source registers were checked against registers_size above.
        }
        if (op >= 0x0e && op <= 0x11) {
            const auto &type = image.types[image.prototypes[method.prototype].return_type];
            if ((op == 0x0e) != (type == "V") || (op != 0x0e && unsigned(op - 0x0f) != value_category(type)))
                invalid(method_index, pc, "Return opcode disagrees with method prototype");
        }
        result.at[pc] = static_cast<Index>(result.instructions.size());
        result.instructions.push_back(std::move(ins));
        pc += entry.width;
    }
    std::set<std::uint32_t> handlers;
    const auto boundary = [&](std::uint32_t pc) {
        return pc < result.at.size() && result.at[pc] != no_index;
    };
    if (!boundary(0))
        invalid(method_index, 0, "Method entry is not executable");
    for (std::size_t n = 1; n < data_prefix.size(); ++n)
        data_prefix[n] += data_prefix[n - 1];
    for (const auto &block : code.tries) {
        if (!boundary(block.start) || block.count > units.size() - block.start ||
            (block.start + block.count != units.size() && !boundary(block.start + block.count) &&
             !data_width[block.start + block.count]))
            invalid(method_index, block.start, "Try region splits an instruction");
        if (data_prefix[block.start] != data_prefix[block.start + block.count])
            invalid(method_index, block.start, "Try region includes non-executable payload data");
        for (const auto &handler : block.handlers) {
            if (!boundary(handler.target))
                invalid(method_index, handler.target, "Catch target is not an instruction");
            handlers.insert(handler.target);
        }
    }
    const auto branch_target = [&](std::uint32_t pc, std::int32_t displacement) {
        const auto target = std::int64_t(pc) + displacement;
        if (target < 0 || target >= static_cast<std::int64_t>(units.size()) ||
            !boundary(static_cast<std::uint32_t>(target)))
            invalid(method_index, pc, "Branch target is not a valid instruction boundary");
        const auto target_op = result.instructions[result.at[static_cast<std::size_t>(target)]].opcode;
        if (target_op >= 0x0a && target_op <= 0x0d)
            invalid(method_index, pc, "Branch enters result/exception instruction");
        return static_cast<std::uint32_t>(target);
    };
    std::uint32_t switch_edges = 0;
    for (std::size_t n = 0; n < result.instructions.size(); ++n) {
        auto &ins = result.instructions[n];
        const auto op = ins.opcode;
        if ((op >= 0x28 && op <= 0x2a) || (op >= 0x32 && op <= 0x3d)) {
            // DEX permits a zero displacement only for goto/32. Verification
            // checks structure, while the interpreter's instruction budget
            // bounds execution of legal loops.
            if (!ins.branch && op != 0x2a)
                invalid(method_index, ins.pc, "Branch target is not a valid instruction boundary");
            (void)branch_target(ins.pc, ins.branch);
        }
        if (op == 0x2b || op == 0x2c) {
            const bool sparse = op == 0x2c;
            const auto location = std::int64_t(ins.pc) + ins.branch;
            if (location < 0 || location >= static_cast<std::int64_t>(units.size()) ||
                data_width[static_cast<std::size_t>(location)] < (sparse ? 2u : 4u) ||
                units[static_cast<std::size_t>(location)] != (sparse ? 0x0200 : 0x0100))
                invalid(method_index, ins.pc, "Switch does not reference a complete matching payload");
            const auto payload = static_cast<std::uint32_t>(location);
            const auto count = std::uint32_t(units[payload + 1]);
            if (count > 65536 - switch_edges)
                invalid(method_index, ins.pc, "Switch case edge budget exceeded", "VERIFY_LIMIT");
            switch_edges += count;
            if (sparse) {
                ins.switch_keys.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i)
                    ins.switch_keys.push_back(signed32(payload + 2 + i * 2));
            } else
                ins.switch_first = signed32(payload + 2);
            ins.switch_targets.reserve(count);
            const auto targets = payload + (sparse ? 2 + count * 2 : 4);
            for (std::uint32_t i = 0; i < count; ++i)
                ins.switch_targets.push_back(branch_target(ins.pc, signed32(targets + i * 2)));
        }
        if (op >= 0x0a && op <= 0x0c) {
            if (!n)
                invalid(method_index, ins.pc, "move-result without producer");
            const auto &previous = result.instructions[n - 1];
            if (previous.next != ins.pc)
                invalid(method_index, ins.pc, "move-result is not adjacent to its producer");
            unsigned category = 2;
            if (invoke(previous.opcode)) {
                const auto &type =
                    image.types[image.prototypes[image.methods[previous.index].prototype].return_type];
                if (type == "V")
                    invalid(method_index, ins.pc, "move-result follows void invocation");
                category = value_category(type);
            } else if (previous.opcode != 0x24 && previous.opcode != 0x25)
                invalid(method_index, ins.pc, "move-result without invocation");
            if (category != unsigned(op - 0x0a))
                invalid(method_index, ins.pc, "move-result kind mismatch");
            if (handlers.contains(ins.pc))
                invalid(method_index, ins.pc, "Catch enters move-result");
        }
        if (op == 0x0d && !handlers.contains(ins.pc))
            invalid(method_index, ins.pc, "move-exception outside handler entry");
        const auto terminal = (op >= 0x0e && op <= 0x11) || op == 0x27 || (op >= 0x28 && op <= 0x2a);
        if (!terminal && ins.next == units.size())
            invalid(method_index, ins.pc, "Execution can fall off method end");
        if (!terminal && !boundary(ins.next))
            invalid(method_index, ins.pc, "Execution falls into non-executable payload data");
        if (!terminal && result.instructions[result.at[ins.next]].opcode == 0x0d)
            invalid(method_index, ins.pc, "Normal execution enters move-exception");
    }
    return result;
}
} // namespace aether::dex

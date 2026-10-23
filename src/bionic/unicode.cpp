#include "unicode.hpp"
#include "ctype.hpp"
#include "../../third_party/unicode/ucd16.hpp"

namespace aether::bionic {
namespace {
constexpr std::array ascii{
    CharacterOperation::alnum,CharacterOperation::alpha,CharacterOperation::blank,
    CharacterOperation::digit,CharacterOperation::graph,CharacterOperation::lower,
    CharacterOperation::print,CharacterOperation::punct,CharacterOperation::space,
    CharacterOperation::upper,CharacterOperation::xdigit,
    CharacterOperation::to_lower,CharacterOperation::to_upper};
template<std::size_t N>
std::uint32_t map(const std::array<unicode16::Mapping,N> &table,std::uint32_t point) noexcept {
    std::size_t low=0,high=N;
    while(low<high){
        const auto middle=low+(high-low)/2;
        if(point<table[middle].point)high=middle;
        else if(point>table[middle].point)low=middle+1;
        else return table[middle].result;
    }
    return point;
}
constexpr bool valid_data(){
    std::uint32_t end=127;
    for(const auto &range:unicode16::properties){
        if(range.first<=end || range.first>range.last || range.last>0x10ffff ||
           !range.flags || range.flags>0x7ff)return false;
        end=range.last;
    }
    const auto valid_maps=[](const auto &table){
        std::uint32_t previous=127;
        for(const auto &entry:table){
            if(entry.point<=previous || entry.point>0x10ffff || entry.result>0x10ffff ||
               (entry.point>=0xd800 && entry.point<=0xdfff) ||
               (entry.result>=0xd800 && entry.result<=0xdfff) || entry.point==entry.result)return false;
            previous=entry.point;
        }
        return true;
    };
    return valid_maps(unicode16::lowercase) && valid_maps(unicode16::uppercase);
}
static_assert(valid_data());
}
std::uint32_t native_unicode(UnicodeOperation operation,std::uint32_t point) noexcept {
    const auto index=static_cast<unsigned>(operation);
    if(index>=ascii.size())return 0;
    if(point<128)return native_character(ascii[index],point);
    const bool mapping=operation==UnicodeOperation::to_lower || operation==UnicodeOperation::to_upper;
    if(point>0x10ffff || (point>=0xd800 && point<=0xdfff))return mapping?point:0;
    if(operation==UnicodeOperation::to_lower)return map(unicode16::lowercase,point);
    if(operation==UnicodeOperation::to_upper)return map(unicode16::uppercase,point);
    std::size_t low=0,high=unicode16::properties.size();
    while(low<high){
        const auto middle=low+(high-low)/2;
        const auto &range=unicode16::properties[middle];
        if(point<range.first)high=middle;
        else if(point>range.last)low=middle+1;
        else return (range.flags&(1U<<index))?1:0;
    }
    return 0;
}
}

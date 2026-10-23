#include "ctype.hpp"
namespace aether::bionic {
std::uint32_t native_character(CharacterOperation operation,std::uint32_t c) noexcept {
    const bool lower=c>='a' && c<='z',upper=c>='A' && c<='Z',digit=c>='0' && c<='9';
    const bool alpha=lower || upper,alnum=alpha || digit,graph=c>=33 && c<=126;
    switch(operation){
    case CharacterOperation::wide_control:return c<=0x1f || (c>=0x7f && c<=0x9f);
    case CharacterOperation::alnum:return alnum;
    case CharacterOperation::alpha:return alpha;
    case CharacterOperation::blank:return c==' ' || c=='\t';
    case CharacterOperation::control:return c<=0x1f || c==0x7f;
    case CharacterOperation::digit:return digit;
    case CharacterOperation::graph:return graph;
    case CharacterOperation::lower:return lower;
    case CharacterOperation::print:return c>=32 && c<=126;
    case CharacterOperation::punct:return graph && !alnum;
    case CharacterOperation::space:return c==' ' || (c>=9 && c<=13);
    case CharacterOperation::upper:return upper;
    case CharacterOperation::xdigit:return digit || (c>='a' && c<='f') || (c>='A' && c<='F');
    case CharacterOperation::to_lower:return upper?c+32:c;
    case CharacterOperation::to_upper:return lower?c-32:c;
    }
    return 0;
}
}

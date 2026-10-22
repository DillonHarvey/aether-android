#include "time_units.hpp"
#include "aether/dex/runtime.hpp"
#include <limits>
namespace aether::dex {
std::optional<std::size_t> time_unit_index(std::string_view name) {
    for(std::size_t n=0;n<time_unit_names.size();++n) if(time_unit_names[n]==name) return n;
    return {};
}
std::optional<std::size_t> time_unit_target(std::string_view method) {
    constexpr std::array<std::string_view,7> methods{"toNanos","toMicros","toMillis","toSeconds","toMinutes","toHours","toDays"};
    for(std::size_t n=0;n<methods.size();++n) if(methods[n]==method) return n;
    return {};
}
std::int64_t convert_time_unit(std::int64_t value,std::size_t source,std::size_t target) {
    constexpr std::array<std::int64_t,7> scales{1,1000,1000000,1000000000,60000000000,3600000000000,86400000000000};
    if(source>=scales.size() || target>=scales.size())
        throw DexError("AETHER_DEX_ENUM_STATE","Invalid TimeUnit ordinal");
    if(scales[source]<=scales[target]) return value/(scales[target]/scales[source]);
    const auto factor=scales[source]/scales[target];
    constexpr auto maximum=std::numeric_limits<std::int64_t>::max(),minimum=std::numeric_limits<std::int64_t>::min();
    if(value>maximum/factor) return maximum;
    if(value<minimum/factor) return minimum;
    return value*factor;
}
} // namespace aether::dex

#pragma once
#include "aether/dex/runtime.hpp"
#include <array>
namespace aether::dex {
inline constexpr std::string_view input_stream_type="Ljava/io/InputStream;";
inline constexpr std::string_view file_input_stream_type="Ljava/io/FileInputStream;";
inline constexpr std::string_view byte_input_stream_type="Ljava/io/ByteArrayInputStream;";
inline constexpr std::string_view reader_type="Ljava/io/Reader;";
inline constexpr std::string_view string_reader_type="Ljava/io/StringReader;";
inline constexpr std::string_view input_reader_type="Ljava/io/InputStreamReader;";
inline constexpr std::string_view buffered_reader_type="Ljava/io/BufferedReader;";
inline constexpr std::string_view print_stream_type="Ljava/io/PrintStream;";
inline bool print_stream_method(std::string_view name,std::string_view signature) {
    return ((name=="print" || name=="println") && signature=="(Ljava/lang/String;)V") ||
           ((name=="println" || name=="flush" || name=="close") && signature=="()V") ||
           (name=="checkError" && signature=="()Z") ||
           (name=="printf" && signature=="(Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintStream;");
}
std::optional<HostClass> stream_class(std::string_view);
struct ManagedStream {
    enum class Kind {input,file,bytes,reader,string,decoder,buffered};
    explicit ManagedStream(Kind kind):kind(kind){}
    ~ManagedStream();
    host::FileResult close_source() noexcept;
    Kind kind;
    std::array<Value,2> roots{}; // Delegate/backing value and real managed char buffer.
    std::unique_ptr<HostInputStream> source;
    std::size_t source_bytes=0,position=0,end=0;
    std::uint64_t provider_generation=0;
    bool initialized=false,initializing=false,closed=false,source_closed=false,skip_lf=false,busy=false;
};
} // namespace aether::dex

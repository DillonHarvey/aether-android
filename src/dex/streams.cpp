#include "streams.hpp"
namespace aether::dex {
std::optional<HostClass> stream_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> closeable{"Ljava/io/Closeable;"},auto_closeable{"Ljava/lang/AutoCloseable;"};
    static constexpr std::array<std::string_view,2> reader_interfaces{"Ljava/lang/Readable;","Ljava/io/Closeable;"};
    if(type=="Ljava/lang/AutoCloseable;" || type=="Ljava/lang/Readable;")return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type=="Ljava/io/Closeable;")return HostClass{"Ljava/lang/Object;",auto_closeable,true,true};
    static constexpr std::array<std::string_view,2> output_interfaces{"Ljava/io/Closeable;","Ljava/io/Flushable;"};
    static constexpr std::array<std::string_view,1> appendable{"Ljava/lang/Appendable;"};
    if(type=="Ljava/io/Flushable;" || type=="Ljava/lang/Appendable;")return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type=="Ljava/io/OutputStream;")return HostClass{"Ljava/lang/Object;",output_interfaces,true};
    if(type=="Ljava/io/FilterOutputStream;")return HostClass{"Ljava/io/OutputStream;"};
    if(type==print_stream_type)return HostClass{"Ljava/io/FilterOutputStream;",appendable};
    if(type==input_stream_type)return HostClass{"Ljava/lang/Object;",closeable,true};
    if(type==reader_type)return HostClass{"Ljava/lang/Object;",reader_interfaces,true};
    if(type==file_input_stream_type || type==byte_input_stream_type)return HostClass{input_stream_type};
    if(type==string_reader_type || type==input_reader_type || type==buffered_reader_type)return HostClass{reader_type};
    if(type=="Ljava/io/IOException;")return HostClass{"Ljava/lang/Exception;"};
    if(type=="Ljava/io/FileNotFoundException;" || type=="Ljava/io/UnsupportedEncodingException;")return HostClass{"Ljava/io/IOException;"};
    return {};
}
host::FileResult ManagedStream::close_source() noexcept {
    if(!source || source_closed)return {0,host::FileError::none};
    source_closed=true;
    return source->close();
}
ManagedStream::~ManagedStream(){(void)close_source();}
} // namespace aether::dex

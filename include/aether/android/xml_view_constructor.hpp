#pragma once
#include "aether/dex/runtime.hpp"
#include <string_view>

namespace aether::android {
// Metadata lookup only: no target initialization or constructor body. Returns
// an authenticated reflected public XML constructor with the SDK accessibility
// flag set. Abstract targets remain discoverable/cacheable; invocation owns the
// real InstantiationException boundary. Caller roots before cache publication.
dex::ObjectId lookup_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          std::string_view descriptor,
                                          dex::ObjectId selected_loader);
// SDK cache invocation: forward the caller's rooted actual per-inflater Object[2]
// unchanged. Core reflection reads live cells after target initialization, so
// reentrant inflater mutations remain observable. No accessibility reset/lookup.
dex::ObjectId invoke_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          dex::ObjectId constructor,
                                          dex::ObjectId actual_arguments);
// Invoke an actual cached constructor without repeating lookup, loader calls or
// setAccessible. Context is nonnull; null attributes are forwarded unchanged.
// Existing core reflection wraps only constructor-body Java exceptions.
dex::ObjectId invoke_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          dex::ObjectId constructor,
                                          dex::ObjectId context,
                                          dex::ObjectId attributes);

// Normal inflater fallback for an original owned View class, after the actual
// themed Context, filters and installed public/private factories have run.
// Uses only this runtime's closed class space and the target's own public
// (Context, nullable AttributeSet) constructor. Null attributes are forwarded
// unchanged. SDK widget construction is separate.
// selected_loader must be the result of the genuine inflater Context's virtual
// getClassLoader call. It is authenticated against this runtime's loader; a
// different loader is unsupported, never replaced with the canonical loader.
// Existing core reflection wraps only constructor-body exceptions in an actual
// InvocationTargetException; the owning inflater applies the outer
// InflateException/cause boundary. No constructor is retried.
// The caller must root the returned ID before another allocation or callback.
dex::ObjectId construct_owned_xml_view(dex::ManagedRuntime &runtime,
                                     std::string_view descriptor,
                                     dex::ObjectId context,
                                     dex::ObjectId attributes,
                                     dex::ObjectId selected_loader);
} // namespace aether::android

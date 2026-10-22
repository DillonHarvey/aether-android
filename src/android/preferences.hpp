#pragma once
#include "aether/dex/runtime.hpp"
#include "aether/host/file_service.hpp"
namespace aether::android {
inline constexpr std::string_view preferences_type="Landroid/content/SharedPreferences;";
inline constexpr std::string_view preferences_editor_type="Landroid/content/SharedPreferences$Editor;";
inline constexpr std::string_view preferences_store_impl="Laether/android/PreferencesStore;";
inline constexpr std::string_view preferences_editor_impl="Laether/android/PreferencesEditor;";
inline constexpr std::string_view preferences_lease_impl="Laether/android/PreferencesLease;";
std::optional<dex::HostClass> preferences_class(std::string_view);
std::string_view preferences_owner(std::string_view) noexcept;
class PreferencesService {
  public:
    PreferencesService(dex::ManagedRuntime &,host::FileService *);
    ~PreferencesService();
    PreferencesService(const PreferencesService&)=delete;
    dex::ObjectId open(dex::ObjectId context,std::u16string_view name,std::int32_t mode);
    std::optional<dex::Value> invoke(dex::Index method,std::span<const dex::Value> args);
    std::optional<dex::Value> invoke(std::string_view owner,std::string_view name,std::string_view signature,std::span<const dex::Value> args);
    void close();
    std::uint64_t denials() const noexcept;
  private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
}

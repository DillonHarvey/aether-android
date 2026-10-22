#pragma once
#include "collections.hpp"
#include <functional>
namespace aether::dex {
inline constexpr std::string_view array_deque_type = "Ljava/util/ArrayDeque;";
inline constexpr std::string_view deque_iterator_type = "Laether/internal/DequeIterator;";
std::optional<HostClass> deque_class(std::string_view type);
struct DequeIterator {
    ObjectId backing = 0;
    std::size_t cursor = 0;
    std::optional<std::size_t> last;
    std::uint64_t revision = 0;
    bool reverse = false;
};
class ManagedDeque {
  public:
    std::span<const Value> references() const noexcept { return values_; }
    std::size_t bytes() const noexcept { return values_.capacity() * sizeof(Value); }
    std::uint64_t revision() const noexcept { return revision_; }
    bool initialized() const noexcept { return initialized_; }
    std::optional<Value> invoke(ManagedRuntime &, std::string_view name, std::string_view signature,
                               std::span<const Value>, CollectionBudget,
                               const std::function<bool(ObjectId,ObjectId)> &equal);
    std::optional<Value> iterate(ManagedRuntime &, DequeIterator &, std::string_view name, std::string_view signature);
  private:
    std::vector<Value> values_;
    std::uint64_t revision_ = 0;
    bool initialized_ = false;
    void grow(CollectionBudget);
};
}

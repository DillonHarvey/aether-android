#pragma once
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace aether::dex {
// Append-only pages preserve elements and their interior views while the page
// owners grow. Copies own independent elements. Iterators are not ownership
// handles; clear, assignment and destruction invalidate prior element views.
// As with standard containers, a throwing element move may modify its source:
// structural rollback cannot undo that mutation for a same-table rvalue alias.
template<class TableElement> class StableTable {
  public:
    using value_type=TableElement;
    using size_type=std::size_t;
    using difference_type=std::ptrdiff_t;
    using reference=value_type &;
    using const_reference=const value_type &;
  private:
    static constexpr size_type page_limit=64;
    using Page=std::vector<value_type>;
    struct State {std::vector<std::unique_ptr<Page>> pages;};
    // Moving only this pointer avoids even MSVC Debug's vector-proxy allocation.
    std::unique_ptr<State> state_;
    size_type size_=0;
    template<bool TableConstant> class BasicIterator {
        friend class StableTable;
        template<bool> friend class BasicIterator;
        using Table=std::conditional_t<TableConstant,const StableTable,StableTable>;
        Table *owner_=nullptr;
        size_type index_=0;
        BasicIterator(Table *stable_table_owner,size_type stable_table_index) noexcept
            :owner_(stable_table_owner),index_(stable_table_index) {}
      public:
        using iterator_category=std::forward_iterator_tag;
        using iterator_concept=std::forward_iterator_tag;
        using value_type=TableElement;
        using difference_type=std::ptrdiff_t;
        using reference=std::conditional_t<TableConstant,const value_type &,value_type &>;
        using pointer=std::conditional_t<TableConstant,const value_type *,value_type *>;
        BasicIterator() noexcept=default;
        template<bool TableOther> requires (TableConstant && !TableOther)
        BasicIterator(const BasicIterator<TableOther> &stable_table_other) noexcept
            :owner_(stable_table_other.owner_),index_(stable_table_other.index_) {}
        reference operator*() const noexcept {return (*owner_)[index_];}
        pointer operator->() const noexcept {return std::addressof((*owner_)[index_]);}
        BasicIterator &operator++() noexcept {++index_;return *this;}
        BasicIterator operator++(int) noexcept {auto stable_table_previous=*this;++*this;return stable_table_previous;}
        template<bool TableOther> bool operator==(const BasicIterator<TableOther> &stable_table_other) const noexcept {
            return owner_==stable_table_other.owner_ && index_==stable_table_other.index_;
        }
    };
  public:
    using iterator=BasicIterator<false>;
    using const_iterator=BasicIterator<true>;
    StableTable() noexcept=default;
    StableTable(std::initializer_list<value_type> stable_table_values) {
        for(const auto &stable_table_value:stable_table_values)emplace_back(stable_table_value);
    }
    StableTable(const StableTable &stable_table_other) {
        // Fresh destination pages always reserve 64 slots. A copied Page vector
        // could otherwise have smaller capacity and relocate its elements later.
        for(const auto &stable_table_value:stable_table_other)emplace_back(stable_table_value);
    }
    StableTable(StableTable &&stable_table_other) noexcept
        :state_(std::move(stable_table_other.state_)),size_(std::exchange(stable_table_other.size_,0)) {}
    StableTable &operator=(const StableTable &stable_table_other) {
        if(this!=&stable_table_other){StableTable stable_table_replacement(stable_table_other);swap(stable_table_replacement);}
        return *this;
    }
    StableTable &operator=(StableTable &&stable_table_other) noexcept {
        if(this!=&stable_table_other){state_=std::move(stable_table_other.state_);size_=std::exchange(stable_table_other.size_,0);}
        return *this;
    }
    StableTable &operator=(std::initializer_list<value_type> stable_table_values) {
        StableTable stable_table_replacement(stable_table_values);swap(stable_table_replacement);return *this;
    }
    bool empty() const noexcept {return size_==0;}
    size_type size() const noexcept {return size_;}
    reference operator[](size_type stable_table_index) noexcept {
        return (*state_->pages[stable_table_index/page_limit])[stable_table_index%page_limit];
    }
    const_reference operator[](size_type stable_table_index) const noexcept {
        return (*state_->pages[stable_table_index/page_limit])[stable_table_index%page_limit];
    }
    reference at(size_type stable_table_index) {
        if(stable_table_index>=size_)throw std::out_of_range("StableTable index outside range");
        return (*this)[stable_table_index];
    }
    const_reference at(size_type stable_table_index) const {
        if(stable_table_index>=size_)throw std::out_of_range("StableTable index outside range");
        return (*this)[stable_table_index];
    }
    reference front() noexcept {return (*this)[0];}
    const_reference front() const noexcept {return (*this)[0];}
    reference back() noexcept {return (*this)[size_-1];}
    const_reference back() const noexcept {return (*this)[size_-1];}
    iterator begin() noexcept {return iterator(this,0);}
    iterator end() noexcept {return iterator(this,size_);}
    const_iterator begin() const noexcept {return const_iterator(this,0);}
    const_iterator end() const noexcept {return const_iterator(this,size_);}
    const_iterator cbegin() const noexcept {return begin();}
    const_iterator cend() const noexcept {return end();}
    template<class... TableArguments> reference emplace_back(TableArguments &&...stable_table_arguments) {
        bool stable_table_new_state=false,stable_table_new_page=false;
        try {
            if(!state_){state_=std::make_unique<State>();stable_table_new_state=true;}
            auto &stable_table_pages=state_->pages;
            if(stable_table_pages.empty() || stable_table_pages.back()->size()==page_limit) {
                auto stable_table_page=std::make_unique<Page>();
                stable_table_page->reserve(page_limit); // Once only; no page exceeds 64 elements.
                stable_table_pages.push_back(std::move(stable_table_page));
                stable_table_new_page=true; // Attach ownership before element construction.
            }
            auto &stable_table_value=stable_table_pages.back()->emplace_back(std::forward<TableArguments>(stable_table_arguments)...);
            ++size_;
            return stable_table_value;
        } catch(...) {
            if(stable_table_new_page)state_->pages.pop_back();
            if(stable_table_new_state)state_.reset();
            throw;
        }
    }
    void push_back(const value_type &stable_table_value) {emplace_back(stable_table_value);}
    void push_back(value_type &&stable_table_value) {emplace_back(std::move(stable_table_value));}
    void clear() noexcept {state_.reset();size_=0;}
    void swap(StableTable &stable_table_other) noexcept {
        state_.swap(stable_table_other.state_);std::swap(size_,stable_table_other.size_);
    }
};
} // namespace aether::dex

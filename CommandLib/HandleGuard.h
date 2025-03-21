#pragma once

#include <Windows.h>

namespace CommandLib {
    template <typename HandleType>
    class HandleGuardImpl {
        HandleType handle_;

    public:
        explicit HandleGuardImpl(HandleType handle = nullptr) : handle_(handle) {}

        ~HandleGuardImpl() {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
                CloseHandle(handle_);
        }

        HandleType get() const { return handle_; }
        HandleType* get_pointer() { return &handle_; }
        operator HandleType() const { return handle_; }

        // Disable copy semantics
        HandleGuardImpl(const HandleGuardImpl&) = delete;
        HandleGuardImpl& operator=(const HandleGuardImpl&) = delete;

        // Enable move semantics
        HandleGuardImpl(HandleGuardImpl&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

        HandleGuardImpl& operator=(HandleGuardImpl&& other) noexcept {
            if (this != &other) {
                if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
                    CloseHandle(handle_);
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        void reset(HandleType handle = nullptr) {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
                CloseHandle(handle_);
            handle_ = handle;
        }
    };

    using HandleGuard = HandleGuardImpl<HANDLE>;
}


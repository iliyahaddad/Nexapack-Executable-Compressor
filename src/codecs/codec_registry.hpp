#ifndef NEXAPACK_CODECS_CODEC_REGISTRY_HPP
#define NEXAPACK_CODECS_CODEC_REGISTRY_HPP

#include "core/codec_interface.hpp"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {

// Central registry of available codecs. The CLI and GUI both query this rather
// than hardcoding codec names, so only implemented codecs are exposed.
class CodecRegistry {
public:
    CodecRegistry();
    ~CodecRegistry();

    CodecRegistry(const CodecRegistry&) = delete;
    CodecRegistry& operator=(const CodecRegistry&) = delete;

    // Register a codec (takes ownership).
    void register_codec(CodecPtr codec);

    // Look up by id. Returns nullptr if not registered.
    [[nodiscard]] Codec* find(std::string_view id) const noexcept;

    // Look up by index.
    [[nodiscard]] Codec* at(size_t index) const noexcept;
    [[nodiscard]] size_t count() const noexcept;

    // List all registered codec ids.
    [[nodiscard]] std::vector<std::string> ids() const noexcept;

private:
    std::map<std::string, CodecPtr> codecs_;
    std::vector<Codec*> order_;
};

} // namespace nexapack

#endif // NEXAPACK_CODECS_CODEC_REGISTRY_HPP


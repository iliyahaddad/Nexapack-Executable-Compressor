#include "codecs/codec_registry.hpp"
#include "codecs/lz4/lz4_codec.hpp"
#include "codecs/lzma/lzma_codec.hpp"
#include "codecs/store/store_codec.hpp"
#include "codecs/zstd/zstd_codec.hpp"
#include "core/logging.hpp"

namespace nexapack {

CodecRegistry::CodecRegistry() {
    register_codec(std::make_unique<StoreCodec>());
    register_codec(std::make_unique<ZstdCodec>());
    register_codec(std::make_unique<Lz4Codec>());
    register_codec(std::make_unique<LzmaCodec>());
    nexapack::nxp_log(nexapack::LogLevel::Info, "codec registry initialized with " + std::to_string(count()) + " codecs");
}

CodecRegistry::~CodecRegistry() = default;

void CodecRegistry::register_codec(CodecPtr codec) {
    if (!codec) {
        return;
    }
    std::string id(codec->id());
    codecs_[id] = std::move(codec);
    order_.push_back(codecs_[id].get());
}

Codec* CodecRegistry::find(std::string_view id) const noexcept {
    auto it = codecs_.find(std::string(id));
    if (it == codecs_.end()) {
        return nullptr;
    }
    return it->second.get();
}

Codec* CodecRegistry::at(size_t index) const noexcept {
    if (index >= order_.size()) {
        return nullptr;
    }
    return order_[index];
}

size_t CodecRegistry::count() const noexcept { return order_.size(); }

std::vector<std::string> CodecRegistry::ids() const noexcept {
    std::vector<std::string> out;
    out.reserve(codecs_.size());
    for (const auto& kv : codecs_) {
        out.push_back(kv.first);
    }
    return out;
}

} // namespace nexapack



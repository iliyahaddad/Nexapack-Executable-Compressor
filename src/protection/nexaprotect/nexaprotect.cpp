#include "protection/nexaprotect/nexaprotect.hpp"
#include "protection/integrity/integrity.hpp"
#include "protection/mba/mba.hpp"
#include "protection/section_protection/section_protection.hpp"
#include "protection/symbols/symbols.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>

namespace nexapack {
namespace nexaprotect {

bool profile_includes(ProtectionProfile profile, ProtectionFeature feature) {
    switch (profile) {
        case ProtectionProfile::None:
            return false;
        case ProtectionProfile::Basic:
            return feature == ProtectionFeature::AntiTamper;
        case ProtectionProfile::Standard:
            return feature == ProtectionFeature::AntiTamper ||
                   feature == ProtectionFeature::SymbolStripping;
        case ProtectionProfile::Advanced:
        case ProtectionProfile::Maximum:
            return feature == ProtectionFeature::AntiTamper ||
                   feature == ProtectionFeature::SymbolStripping ||
                   feature == ProtectionFeature::SectionEncryption;
    }
    return false;
}

Error apply_protection(std::string_view input,
                       const ProtectionConfig& config,
                       ProtectionResult& out) {
    out = ProtectionResult{};

    if (input.empty()) {
        out.error = make_error(ErrorCategory::InvalidArgument, 1,
                               "empty input buffer");
        return out.error;
    }

    std::vector<uint8_t> data(input.begin(), input.end());

    // Determine effective features from profile + explicit config overrides.
    bool do_symbols = config.strip_symbols ||
                      profile_includes(config.profile,
                                       ProtectionFeature::SymbolStripping);
    bool do_sections = config.protect_sections ||
                       profile_includes(config.profile,
                                        ProtectionFeature::SectionEncryption);
    bool do_mba = config.apply_mba ||
                  profile_includes(config.profile,
                                   ProtectionFeature::MBATransformations);
    bool do_integrity = config.integrity_check ||
                        profile_includes(config.profile,
                                         ProtectionFeature::AntiTamper);

    // 1. Symbol protection
    if (do_symbols) {
        symbols::SymbolPolicy policy = symbols::SymbolPolicy::StripNonRuntime;
        if (config.preserve_debug) {
            policy = symbols::SymbolPolicy::PreserveAll;
        }
        symbols::SymbolResult sres;
        Error err = symbols::process_symbols(
            std::string_view(reinterpret_cast<const char*>(data.data()),
                             data.size()),
            policy, sres);
        if (!err.ok()) {
            out.error = err;
            return out.error;
        }
        if (!sres.processed_data.empty()) {
            data = std::move(sres.processed_data);
        }
        out.symbols_stripped = (sres.symbols_removed > 0);
        out.overhead_bytes += sres.bytes_saved;
    }

    // 2. Section protection
    if (do_sections) {
        section_protection::SectionMode mode =
            (config.profile == ProtectionProfile::Advanced ||
             config.profile == ProtectionProfile::Maximum)
                ? section_protection::SectionMode::EncryptSelected
                : section_protection::SectionMode::None;
        section_protection::SectionResult secres;
        Error err = section_protection::protect_sections(
            std::string_view(reinterpret_cast<const char*>(data.data()),
                             data.size()),
            mode, secres);
        if (!err.ok()) {
            out.error = err;
            return out.error;
        }
        if (!secres.protected_data.empty()) {
            data = std::move(secres.protected_data);
        }
        out.sections_protected = secres.sections_protected;
        out.encrypted_sections = secres.encrypted_sections;
        // Store encrypted section metadata for runtime stub decryption.
        for (auto& es : secres.encrypted_sections) {
            out.protection_meta.push_back(static_cast<uint8_t>(es.first & 0xFF));
            out.protection_meta.push_back(static_cast<uint8_t>((es.first >> 8) & 0xFF));
            uint64_t key = es.second;
            for (int b = 0; b < 8; b++) {
                out.protection_meta.push_back(static_cast<uint8_t>((key >> (b * 8)) & 0xFF));
            }
        }
    }

    // 3. MBA transformations
    if (do_mba) {
        mba::MBAResult mres;
        Error err = mba::apply_mba(
            std::string_view(reinterpret_cast<const char*>(data.data()),
                             data.size()),
            static_cast<mba::MBAIntensity>(config.mba_intensity), mres);
        if (!err.ok()) {
            out.error = err;
            return out.error;
        }
        if (!mres.transformed_data.empty()) {
            data = std::move(mres.transformed_data);
        }
        out.mba_applied = mres.semantically_equivalent;
    }

    // 4. Integrity / anti-tamper (computed last over final protected data)
    if (do_integrity) {
        integrity::IntegrityResult ires;
        Error err = integrity::compute_integrity(
            std::string_view(reinterpret_cast<const char*>(data.data()),
                             data.size()),
            ires);
        if (!err.ok()) {
            out.error = err;
            return out.error;
        }
        out.integrity_enabled = ires.valid;
        // Store checksum as protection metadata (4 bytes LE)
        out.protection_meta.resize(4);
        std::memcpy(out.protection_meta.data(), &ires.checksum, 4);
    }

    out.protected_data = std::move(data);
    nexapack::nxp_log(nexapack::LogLevel::Info, "nexaprotect: protection applied (profile=" +
                      std::to_string(static_cast<uint32_t>(config.profile)) +
                      ")");
    return ok_error();
}

Error verify_protection(std::string_view protected_data,
                        std::string_view protection_meta,
                        bool& out_tampered) {
    return integrity::verify_integrity(protected_data, protection_meta,
                                       out_tampered);
}

} // namespace nexaprotect
} // namespace nexapack



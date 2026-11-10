#ifndef NEXAPACK_CLI_CLI_HPP
#define NEXAPACK_CLI_CLI_HPP

#include "core/codec_interface.hpp"
#include "core/error.hpp"
#include "core/metadata.hpp"
#include "protection/nexaprotect/nexaprotect.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace nexapack {

struct PackOptions {
    std::string input;
    std::string output;
    CompressionProfile profile = CompressionProfile::Balanced;
    std::string codec_id = "auto";
    uint32_t level = 0; // 0 = codec default
    bool force = false;
    bool verbose = false;
    bool json = false;
    std::string protection = "none";
    uint32_t threads = 1;
};

struct CompareOptions {
    std::string input;
    bool verbose = false;
    bool json = false;
};

struct UnpackOptions {
    std::string input;
    std::string output;
    bool force = false;
    bool verbose = false;
    bool json = false;
};

struct InspectOptions {
    std::string input;
    bool verbose = false;
    bool json = false;
};

struct VerifyOptions {
    std::string input;
    bool verbose = false;
    bool json = false;
};

struct BenchmarkOptions {
    std::string input;
    bool verbose = false;
    bool json = false;
};

struct BatchOptions {
    std::string input;
    std::string profile = "balanced";
    std::string codec_id = "auto";
    std::string protection = "none";
    uint32_t level = 6;
    uint32_t threads = 1;
    bool force = false;
    bool verbose = false;
    bool json = false;
};

struct CodecsOptions {
    bool json = false;
};

struct ProfilesOptions {
    bool json = false;
};

struct CommonOptions {
    bool verbose = false;
    bool json = false;
};

class Cli {
public:
    enum class Command {
        None,
        Pack,
        Unpack,
        Inspect,
        Verify,
        Benchmark,
        Compare,
        Codecs,
        Profiles,
        Version,
        Help,
        Batch,
    };

    Cli() = default;

    [[nodiscard]] Error parse(int argc, char* argv[]);

    [[nodiscard]] Command command() const noexcept { return command_; }
    [[nodiscard]] const PackOptions& pack_options() const noexcept { return pack_; }
    [[nodiscard]] const UnpackOptions& unpack_options() const noexcept { return unpack_; }
    [[nodiscard]] const InspectOptions& inspect_options() const noexcept { return inspect_; }
    [[nodiscard]] const VerifyOptions& verify_options() const noexcept { return verify_; }
    [[nodiscard]] const BenchmarkOptions& benchmark_options() const noexcept { return benchmark_; }
    [[nodiscard]] const CompareOptions& compare_options() const noexcept { return compare_; }
    [[nodiscard]] const BatchOptions& batch_options() const noexcept { return batch_; }
    [[nodiscard]] const CodecsOptions& codecs_options() const noexcept { return codecs_; }
    [[nodiscard]] const ProfilesOptions& profiles_options() const noexcept { return profiles_; }
    [[nodiscard]] const CommonOptions& common() const noexcept { return common_; }
    [[nodiscard]] const std::vector<std::string>& positional() const noexcept { return positional_; }

private:
    Command command_ = Command::None;
    PackOptions pack_;
    UnpackOptions unpack_;
    InspectOptions inspect_;
    VerifyOptions verify_;
    BenchmarkOptions benchmark_;
    CompareOptions compare_;
    BatchOptions batch_;
    CodecsOptions codecs_;
    ProfilesOptions profiles_;
    CommonOptions common_;
    std::vector<std::string> positional_;
};

} // namespace nexapack

#endif // NEXAPACK_CLI_CLI_HPP
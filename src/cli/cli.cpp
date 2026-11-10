#include "cli/cli.hpp"
#include "core/analyzer/analyzer.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <iostream>
#include <string>

namespace nexapack {

namespace {

std::string command_to_string(Cli::Command c) {
    switch (c) {
        case Cli::Command::Pack: return "pack";
        case Cli::Command::Unpack: return "unpack";
        case Cli::Command::Inspect: return "inspect";
        case Cli::Command::Verify: return "verify";
        case Cli::Command::Benchmark: return "benchmark";
        case Cli::Command::Codecs: return "codecs";
        case Cli::Command::Profiles: return "profiles";
        case Cli::Command::Version: return "version";
        case Cli::Command::Help: return "help";
        default: return "none";
    }
}

bool is_flag(std::string_view s) { return s.size() >= 2 && s[0] == '-'; }

std::string_view strip_leading_dashes(std::string_view s) {
    while (!s.empty() && s[0] == '-') s.remove_prefix(1);
    return s;
}

} // namespace

Error Cli::parse(int argc, char* argv[]) {
    if (argc < 2) {
        command_ = Cli::Command::Help;
        return ok_error();
    }

    std::string first = argv[1];
    if (first == "pack") {
        command_ = Cli::Command::Pack;
    } else if (first == "unpack") {
        command_ = Cli::Command::Unpack;
    } else if (first == "inspect") {
        command_ = Cli::Command::Inspect;
    } else if (first == "verify") {
        command_ = Cli::Command::Verify;
    } else if (first == "benchmark") {
        command_ = Cli::Command::Benchmark;
    } else if (first == "compare") {
        command_ = Cli::Command::Compare;
    } else if (first == "codecs") {
        command_ = Cli::Command::Codecs;
    } else if (first == "profiles") {
        command_ = Cli::Command::Profiles;
    } else if (first == "version") {
        command_ = Cli::Command::Version;
    } else if (first == "help" || first == "--help" || first == "-h") {
        command_ = Cli::Command::Help;
    } else {
        return make_error(ErrorCategory::InvalidArgument, 1,
                          "unknown command: " + first);
    }

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        std::string_view sv = arg;

        if (command_ == Cli::Command::Pack) {
            if (sv == "-o" || sv == "--output") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 2,
                                      "-o requires an output path");
                pack_.output = argv[++i];
            } else if (sv == "--profile") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 3,
                                      "--profile requires a value");
                std::string p = argv[++i];
                if (p == "fast") pack_.profile = CompressionProfile::Fast;
                else if (p == "balanced") pack_.profile = CompressionProfile::Balanced;
                else if (p == "maximum") pack_.profile = CompressionProfile::Maximum;
                else if (p == "auto") pack_.profile = CompressionProfile::Auto;
                else if (p == "custom") pack_.profile = CompressionProfile::Custom;
                else
                    return make_error(ErrorCategory::InvalidArgument, 4,
                                      "unknown profile: " + p);
            } else if (sv == "--codec") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 5,
                                      "--codec requires a value");
                pack_.codec_id = argv[++i];
            } else if (sv == "--level") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 6,
                                      "--level requires a number");
                pack_.level = static_cast<uint32_t>(std::stoul(argv[++i]));
            } else if (sv == "--best") {
                pack_.level = 0xFFFFFFFFu; // codec max
            } else if (sv == "--force" || sv == "-f") {
                pack_.force = true;
            } else if (sv == "--verbose" || sv == "-v") {
                pack_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                pack_.json = true;
                common_.json = true;
            } else if (sv == "--protection") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 12,
                                      "--protection requires a value");
                pack_.protection = argv[++i];
            } else if (sv == "--threads") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 13,
                                      "--threads requires a number");
                pack_.threads = static_cast<uint32_t>(std::stoul(argv[++i]));
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 7,
                                  "unknown option: " + arg);
            } else {
                if (pack_.input.empty()) {
                    pack_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Unpack) {
            if (sv == "-o" || sv == "--output") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 8,
                                      "-o requires an output path");
                unpack_.output = argv[++i];
            } else if (sv == "--force" || sv == "-f") {
                unpack_.force = true;
            } else if (sv == "--verbose" || sv == "-v") {
                unpack_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                unpack_.json = true;
                common_.json = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 9,
                                  "unknown option: " + arg);
            } else {
                if (unpack_.input.empty()) {
                    unpack_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Inspect) {
            if (sv == "--verbose" || sv == "-v") {
                inspect_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                inspect_.json = true;
                common_.json = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 10,
                                  "unknown option: " + arg);
            } else {
                if (inspect_.input.empty()) {
                    inspect_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Verify) {
            if (sv == "--verbose" || sv == "-v") {
                verify_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                verify_.json = true;
                common_.json = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 10,
                                  "unknown option: " + arg);
            } else {
                if (verify_.input.empty()) {
                    verify_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Benchmark) {
            if (sv == "--verbose" || sv == "-v") {
                benchmark_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                benchmark_.json = true;
                common_.json = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 10,
                                  "unknown option: " + arg);
            } else {
                if (benchmark_.input.empty()) {
                    benchmark_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Compare) {
            if (sv == "--verbose" || sv == "-v") {
                common_.verbose = true;
            } else if (sv == "--json") {
                common_.json = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 10,
                                  "unknown option: " + arg);
            } else {
                if (compare_.input.empty()) {
                    compare_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else if (command_ == Cli::Command::Batch) {
            if (sv == "--verbose" || sv == "-v") {
                batch_.verbose = true;
                common_.verbose = true;
            } else if (sv == "--json") {
                batch_.json = true;
                common_.json = true;
            } else if (sv == "--profile") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 11,
                                      "--profile requires a value");
                batch_.profile = argv[++i];
            } else if (sv == "--codec") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 12,
                                      "--codec requires a value");
                batch_.codec_id = argv[++i];
            } else if (sv == "--protection") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 13,
                                      "--protection requires a value");
                batch_.protection = argv[++i];
            } else if (sv == "--threads") {
                if (i + 1 >= argc)
                    return make_error(ErrorCategory::InvalidArgument, 14,
                                      "--threads requires a number");
                batch_.threads = static_cast<uint32_t>(std::stoul(argv[++i]));
            } else if (sv == "--force" || sv == "-f") {
                batch_.force = true;
            } else if (is_flag(sv)) {
                return make_error(ErrorCategory::InvalidArgument, 14,
                                  "unknown option: " + arg);
            } else {
                if (batch_.input.empty()) {
                    batch_.input = arg;
                } else {
                    positional_.push_back(arg);
                }
            }
        } else {
            if (is_flag(sv)) {
                if (sv == "--verbose" || sv == "-v") {
                    common_.verbose = true;
                } else if (sv == "--json") {
                    common_.json = true;
                } else {
                    return make_error(ErrorCategory::InvalidArgument, 11,
                                      "unknown option: " + arg);
                }
            } else {
                positional_.push_back(arg);
            }
        }
    }

    if (command_ == Cli::Command::Pack && pack_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 12,
                          "pack requires an input file");
    }
    if (command_ == Cli::Command::Unpack && unpack_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 13,
                          "unpack requires an input file");
    }
    if (command_ == Cli::Command::Inspect && inspect_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 14,
                          "inspect requires an input file");
    }
    if (command_ == Cli::Command::Verify && verify_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 15,
                          "verify requires an input file");
    }
    if (command_ == Cli::Command::Benchmark && benchmark_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 16,
                          "benchmark requires an input file");
    }
    if (command_ == Cli::Command::Batch && batch_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 17,
                          "batch requires an input file");
    }
    if (command_ == Cli::Command::Compare && compare_.input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 18,
                          "compare requires an input file");
    }

    nexapack::nxp_log(nexapack::LogLevel::Debug, "parsed command: " + command_to_string(command_));
    return ok_error();
}

} // namespace nexapack



#include "core/error.hpp"

// Error.cpp is intentionally minimal: all Error construction is inline in the
// header. This translation unit exists so the error module has a stable ABI
// boundary and a place to add shared error-formatting logic later.

namespace nexapack {

} // namespace nexapack



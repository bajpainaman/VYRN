/* ef_vi and DPDK fast paths, inlined into Rust through -C linker-plugin-lto (spec/11-build.md §4).
 * 100-300 lines (tools/shim-gate). No globals, no malloc, no stack arrays (§4.5). */
#include "shim.h"

uint32_t vyns_abi_version(void) { return VYNS_ABI_VERSION; }

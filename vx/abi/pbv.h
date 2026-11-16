/* C ABI shared by Rust and Vx: structs, rings, entry points (spec/11-build.md §5.1).
 * Libraries export only pbo_* (oracle) and pbv_* (client) symbols; CI checks with nm -D. */
#ifndef VYRN_PBV_H
#define VYRN_PBV_H

#include <stddef.h>
#include <stdint.h>

/* Oracle (§5.2, 05): oracle_new / oracle_step / oracle_state_hash. */
typedef struct pbo_oracle pbo_oracle;

/* Client (§5.3). */
typedef struct pbv_client pbv_client;

#endif /* VYRN_PBV_H */

/* Source of tools/asm-gate/fixtures/*/disasm.txt. Regenerate with, for a in x86_64 aarch64:
 *   clang --target=$a-linux-gnu -O2 -fPIC -shared -nostdlib -fuse-ld=lld \
 *     -Wl,--unresolved-symbols=ignore-all hot.c -o hot-$a.so
 *   llvm-objdump -d --no-show-raw-insn --symbolize-operands hot-$a.so
 * (clang and llvm-objdump 23.1.6 on Debian, the orb toolchain of 11 §4.2.) */
extern int ef_vi_transmit(int);
extern void *__rust_alloc(unsigned long, unsigned long);
extern void _ZN4core9panicking18panic_bounds_check17h0123456789abcdefE(unsigned long, unsigned long) __attribute__((noreturn));
extern int (*fp)(int);
extern int helper(int x);
int tbl[8];
int vyrn_lane_rx_batch(unsigned n){ int s=0; for(unsigned i=0;i<n;i++){ s+=helper((int)i); if(s>100) s+=fp(s);} if(n>=8) _ZN4core9panicking18panic_bounds_check17h0123456789abcdefE(n,8); s+=tbl[n]; if(n>5) return ef_vi_transmit(s); __rust_alloc(8,8); return s;}
int vyrn_bbo_step(int n){ if (n > 3) return helper(n); return n + 1; }

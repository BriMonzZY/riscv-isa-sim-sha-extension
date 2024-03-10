#ifndef _RISCV_SHA2_ROCC_H
#define _RISCV_SHA2_ROCC_H

#include "rocc.h"
#include "mmu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHA256_DIGEST_SIZE (256 / 8)

class sha2_rocc_t : public extension_t {
public:
  sha2_rocc_t() {};

  const char* name() { return "sha2"; }

  void reset() {
    msg_addr = 0;
    hash_addr = 0;
    msg_len = 0;
  }

  reg_t custom1(rocc_insn_t insn, reg_t xs1, reg_t xs2)
  {
    switch (insn.funct) {
      case 0:
        msg_addr = xs1;
        hash_addr = xs2;
        break;
      case 1:
        msg_len = xs1;

        //read message into buffer
        unsigned char* input;
        input  = (unsigned char*)malloc(msg_len*sizeof(char));
        for(uint32_t i = 0; i < msg_len; i++)
          input[i] = p->get_mmu()->load_uint8(msg_addr + i);
          
        unsigned char output[SHA256_DIGEST_SIZE];
        sha256ONE(input, msg_len, output);

        //write output
        for(uint32_t i = 0; i < SHA256_DIGEST_SIZE; i++)
          p->get_mmu()->store_uint8(hash_addr + i, output[i]);
        
        //clean up
        free(input);

        break;
      case 2:
        break;
      default:
        illegal_instruction();
    }
    return -1;  // in all cases, the accelerator returns nothing
  }

  virtual std::vector<insn_desc_t> get_instructions();
  virtual std::vector<disasm_insn_t*> get_disasms();

private:

  reg_t msg_addr;
  reg_t hash_addr;
  reg_t msg_len;

#define SHA256_SIZE_BYTES 32

typedef struct {
  uint8_t  buf[64];
  uint32_t hash[8];
  uint32_t bits[2];
  uint32_t len;
  uint32_t rfu__;
  uint32_t W[64];
} sha256_context;

void _addbits(sha256_context *ctx, uint32_t n);
void _hashop(sha256_context *ctx);
void sha256Init(sha256_context *ctx);
void sha256Hash(sha256_context *ctx, const void *data, size_t len);
void sha256Done(sha256_context *ctx, uint8_t *hash);
void sha256ONE(const void *data, size_t len, uint8_t *hash);

};

REGISTER_EXTENSION(sha2, []() { return new sha2_rocc_t; })  // 注册扩展

#endif

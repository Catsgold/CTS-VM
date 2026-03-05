#pragma once

#include <stdint.h>

#define CLOSURE_COUNT 256
#define REG_COUNT 256
#define MAX_CYCLES 0xFFFFFF

#define RAM_SIZE (2048 * 2048)
#define STACK_SIZE (RAM_SIZE / 4)
#define STACK_TOP RAM_SIZE 
#define STACK_BOTTOM (STACK_TOP - STACK_SIZE)
#define RAMBLOCK_SIZE STACK_SIZE
#define RAMBLOCK_PTR (STACK_BOTTOM - RAMBLOCK_SIZE)

typedef enum _ctsvm_result 
{
    ctsvm_success = 0,
    ctsvm_invalid_arg,
    ctsvm_halt,
    ctsvm_access_violation,
    ctsvm_buffer_overflow,
} ctsvm_result;

typedef enum _ctsvm_opcode
{
    ctsvm_op_nop = 0,
    ctsvm_op_halt,
    ctsvm_op_cmp,
    ctsvm_op_cmp8,
    ctsvm_op_cmp16,
    ctsvm_op_cmp32,
    ctsvm_op_cmp64,
    
    ctsvm_op_push,
    ctsvm_op_push8,
    ctsvm_op_push16,
    ctsvm_op_push32,
    ctsvm_op_push64,
    ctsvm_op_pop,
    ctsvm_op_call,
    ctsvm_op_call32,
    ctsvm_op_ccall,
    ctsvm_op_ret,
    
    ctsvm_op_mov,
    ctsvm_op_mov8,
    ctsvm_op_mov16,
    ctsvm_op_mov32,
    ctsvm_op_mov64,

    ctsvm_op_lea,
    ctsvm_op_lea8,
    ctsvm_op_lea16,
    ctsvm_op_lea32,
    ctsvm_op_lea64,
    ctsvm_op_leaip,
    ctsvm_op_leaip8,
    ctsvm_op_leaip16,
    ctsvm_op_leaip32,
    ctsvm_op_leaip64,
    ctsvm_op_leasp,
    ctsvm_op_leasp8,
    ctsvm_op_leasp16,
    ctsvm_op_leasp32,
    ctsvm_op_leasp64,

    ctsvm_op_stosp,
    ctsvm_op_stosp8,
    ctsvm_op_stosp16,
    ctsvm_op_stosp32,
    ctsvm_op_stosp64,
    ctsvm_op_lodsp,
    ctsvm_op_subsp,
    ctsvm_op_subsp32,
    ctsvm_op_addsp,
    ctsvm_op_addsp32,

    ctsvm_op_add,
    ctsvm_op_add8,
    ctsvm_op_add16,
    ctsvm_op_add32,
    ctsvm_op_add64,
    ctsvm_op_sub,
    ctsvm_op_sub8,
    ctsvm_op_sub16,
    ctsvm_op_sub32,
    ctsvm_op_sub64,
    ctsvm_op_mul,
    ctsvm_op_mul8,
    ctsvm_op_mul16,
    ctsvm_op_mul32,
    ctsvm_op_mul64,
    ctsvm_op_div,
    ctsvm_op_div8,
    ctsvm_op_div16,
    ctsvm_op_div32,
    ctsvm_op_div64,

    ctsvm_op_and,
    ctsvm_op_and8,
    ctsvm_op_and16,
    ctsvm_op_and32,
    ctsvm_op_and64,
    ctsvm_op_or,
    ctsvm_op_or8,
    ctsvm_op_or16,
    ctsvm_op_or32,
    ctsvm_op_or64,
    ctsvm_op_xor,
    ctsvm_op_xor8,
    ctsvm_op_xor16,
    ctsvm_op_xor32,
    ctsvm_op_xor64,
    ctsvm_op_not,

    ctsvm_op_jmp,
    ctsvm_op_je,
    ctsvm_op_jne,
    ctsvm_op_jl,
    ctsvm_op_jg,
} ctsvm_opcode;

struct _ctsvm_state;

typedef ctsvm_result(*ctsvm_closure)(struct _ctsvm_state *vm);

typedef struct _ctsvm_state
{
    ctsvm_closure closures[CLOSURE_COUNT];
    
    uintptr_t reg[REG_COUNT];
    uint8_t ram[RAM_SIZE];
    
    uintptr_t stack_min;
    uintptr_t stack_max;

    uint8_t *sp;
    uint8_t *ip;
    
    uint8_t cmp;
} ctsvm_state;


ctsvm_state *ctsvm_create_state(void);
void ctsvm_destroy_state(ctsvm_state *vm);

void ctsvm_dump_state(ctsvm_state *vm);

ctsvm_result ctsvm_load(ctsvm_state *vm, const uint8_t *bytes, size_t size);

ctsvm_result ctsvm_push_closure(ctsvm_state *vm, ctsvm_closure closure);
uintptr_t ctsvm_pop(ctsvm_state *vm);

ctsvm_result ctsvm_run(ctsvm_state *vm);
#include "../include/ctsvm.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

static inline uint16_t ctsvm_read16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint32_t ctsvm_read32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t ctsvm_read64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uintptr_t ctsvm_read_ptr(const uint8_t *p)
{
    uintptr_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint8_t ctsvm_fetch8(ctsvm_state *vm)
{
    return *vm->ip++;
}

static inline uint16_t ctsvm_fetch16(ctsvm_state *vm)
{
    uint16_t v = ctsvm_read16(vm->ip);
    vm->ip += sizeof(v);
    return v;
}

static inline uint32_t ctsvm_fetch32(ctsvm_state *vm)
{
    uint32_t v = ctsvm_read32(vm->ip);
    vm->ip += sizeof(v);
    return v;
}

static inline uint64_t ctsvm_fetch64(ctsvm_state *vm)
{
    uint64_t v = ctsvm_read64(vm->ip);
    vm->ip += sizeof(v);
    return v;
}

static inline uintptr_t ctsvm_fetch_ptr(ctsvm_state *vm)
{
    uintptr_t v = ctsvm_read_ptr(vm->ip);
    vm->ip += sizeof(v);
    return v;
}

static inline uintptr_t ctsvm_from_stack(ctsvm_state *vm, int32_t disp)
{
    const uint8_t *sp = vm->sp + disp;

    if ((uintptr_t)sp > vm->stack_max || (uintptr_t)sp < vm->stack_min)
    {
        return 0; // Not access violation, just UB
    }

    uintptr_t v;
    memcpy(&v, sp, sizeof(v));
    return v;
}

static inline ctsvm_result ctsvm_to_stack(ctsvm_state *vm, 
                                          uintptr_t v, int32_t disp)
{
    uint8_t *sp = vm->sp + disp;

    if ((uintptr_t)sp > vm->stack_max || (uintptr_t)sp < vm->stack_min)
    {
        return ctsvm_access_violation;
    }

    memcpy(sp, &v, sizeof(v));
    return ctsvm_success;
}

static inline ctsvm_result ctsvm_push(ctsvm_state *vm, uintptr_t v)
{
    vm->sp -= sizeof(v);
    return ctsvm_to_stack(vm, v, 0);
}

inline uintptr_t ctsvm_pop(ctsvm_state *vm)
{
    vm->sp += sizeof(uintptr_t);
    return ctsvm_from_stack(vm, -8);
}

ctsvm_result ctsvm_push_closure(ctsvm_state *vm, ctsvm_closure closure)
{
    if (!vm || !closure)
    {
        return ctsvm_invalid_arg;
    }
    
    for (int i = 0; i < CLOSURE_COUNT; i++)
    {
        if (!vm->closures[i])
        {
            vm->closures[i] = closure;
            return ctsvm_success;
        }
    }
    
    return ctsvm_buffer_overflow;
}

static inline ctsvm_result ctsvm_run_closure(ctsvm_state *vm, uint8_t i)
{
    ctsvm_closure closure = vm->closures[i];
    if (!closure) 
    {
        return ctsvm_access_violation;
    }
    
    return closure(vm);
}

static inline ctsvm_result ctsvm_step(ctsvm_state *vm)
{
    uint8_t opcode = ctsvm_fetch8(vm);
    switch (opcode)
    {
        case ctsvm_op_nop:
            break;
        case ctsvm_op_halt:
            return ctsvm_halt;
        case ctsvm_op_cmp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            
            vm->cmp = vm->reg[rd] - vm->reg[rs];
            
            break;
        }
        case ctsvm_op_cmp8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            
            vm->cmp = vm->reg[rd] - rs;
            
            break;
        }
        case ctsvm_op_cmp16:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint16_t rs = ctsvm_fetch16(vm);
            
            vm->cmp = vm->reg[rd] - rs;
            
            break;
        }
        case ctsvm_op_cmp32:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint32_t rs = ctsvm_fetch32(vm);
            
            vm->cmp = vm->reg[rd] - rs;
            
            break;
        }
        case ctsvm_op_cmp64:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint64_t rs = ctsvm_fetch64(vm);
            
            vm->cmp = vm->reg[rd] - rs;
            
            break;
        }
        
        case ctsvm_op_push:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            ctsvm_push(vm, vm->reg[rd]);
            
            break;
        }
        case ctsvm_op_push8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            ctsvm_push(vm, rd);
            
            break;
        }
        case ctsvm_op_push16:
        {
            uint16_t rd = ctsvm_fetch16(vm);
            
            ctsvm_push(vm, rd);
            
            break;
        }
        case ctsvm_op_push32:
        {
            uint32_t rd = ctsvm_fetch32(vm);
            
            ctsvm_push(vm, rd);
            
            break;
        }
        case ctsvm_op_push64:
        {
            uint64_t rd = ctsvm_fetch64(vm);
            
            ctsvm_push(vm, rd);
            
            break;
        }
        case ctsvm_op_pop:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            vm->reg[rd] = ctsvm_pop(vm);
            
            break;
        }
        case ctsvm_op_call:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            ctsvm_push(vm, (uintptr_t)vm->ip);
            vm->ip += (int32_t)vm->reg[rd];
            
            break;
        }
        case ctsvm_op_call32:
        {
            ctsvm_push(vm, (uintptr_t)vm->ip + 4);
            vm->ip += (int32_t)ctsvm_fetch32(vm);
            
            break;
        }
        case ctsvm_op_ccall:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            ctsvm_result result = ctsvm_run_closure(vm, rd);
            if (result != ctsvm_success)
            {
                return result;
            }
            
            break;
        }
        case ctsvm_op_ret:
        {
            vm->ip = (uint8_t*)ctsvm_pop(vm);
            
            break;
        }
        
        case ctsvm_op_mov:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            
            vm->reg[rd] = vm->reg[rs];
            
            break;
        }    
        case ctsvm_op_mov8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            
            vm->reg[rd] = rs;
            
            break;
        }            
        case ctsvm_op_mov16:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint16_t rs = ctsvm_fetch16(vm);
            
            vm->reg[rd] = rs;
            
            break;
        }
        case ctsvm_op_mov32:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint32_t rs = ctsvm_fetch32(vm);
            
            vm->reg[rd] = rs;
            
            break;
        }
        case ctsvm_op_mov64:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint64_t rs = ctsvm_fetch64(vm);
            
            vm->reg[rd] = rs;
            
            break;
        }

        case ctsvm_op_lea:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            uint8_t rb = ctsvm_fetch8(vm);

            vm->reg[rd] = vm->reg[rs] + vm->reg[rb];

            break;
        }
        case ctsvm_op_lea8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            uint8_t rb = ctsvm_fetch8(vm);

            vm->reg[rd] = vm->reg[rs] + rb;
            
            break;
        }
        case ctsvm_op_lea16:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            uint16_t rb = ctsvm_fetch16(vm);

            vm->reg[rd] = vm->reg[rs] + rb;
            
            break;
        }
        case ctsvm_op_lea32:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            uint32_t rb = ctsvm_fetch32(vm);

            vm->reg[rd] = vm->reg[rs] + rb;
            
            break;
        }
        case ctsvm_op_lea64:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);
            uint64_t rb = ctsvm_fetch64(vm);

            vm->reg[rd] = vm->reg[rs] + rb;
            
            break;
        }
        case ctsvm_op_leaip:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] = (uintptr_t)(vm->ip - vm->ram) + vm->reg[rs];

            break;
        }
        case ctsvm_op_leaip8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] = (uintptr_t)(vm->ip - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leaip16:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint16_t rs = ctsvm_fetch16(vm);

            vm->reg[rd] = (uintptr_t)(vm->ip - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leaip32:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint32_t rs = ctsvm_fetch32(vm);

            vm->reg[rd] = (uintptr_t)(vm->ip - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leaip64:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint64_t rs = ctsvm_fetch64(vm);

            vm->reg[rd] = (uintptr_t)(vm->ip - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leasp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] = (uintptr_t)(vm->sp - vm->ram) + vm->reg[rs];

            break;
        }
        case ctsvm_op_leasp8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] = (uintptr_t)(vm->sp - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leasp16:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint16_t rs = ctsvm_fetch16(vm);

            vm->reg[rd] = (uintptr_t)(vm->sp - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leasp32:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint32_t rs = ctsvm_fetch32(vm);

            vm->reg[rd] = (uintptr_t)(vm->sp - vm->ram) + rs;
            
            break;
        }
        case ctsvm_op_leasp64:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint64_t rs = ctsvm_fetch64(vm);

            vm->reg[rd] = (uintptr_t)(vm->sp - vm->ram) + rs;
            
            break;
        }

        case ctsvm_op_stosp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            ctsvm_result result = ctsvm_to_stack(vm, vm->reg[rd], rs);
            if (result != ctsvm_success)
            {
                return result;
            }

            break;
        }
        case ctsvm_op_stosp8:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            ctsvm_result result = ctsvm_to_stack(vm, rd, rs);
            if (result != ctsvm_success)
            {
                return result;
            }

            break;
        }
        case ctsvm_op_stosp16:
        {
            uint16_t rd = ctsvm_fetch16(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            ctsvm_result result = ctsvm_to_stack(vm, rd, rs);
            if (result != ctsvm_success)
            {
                return result;
            }

            break;
        }
        case ctsvm_op_stosp32:
        {
            uint32_t rd = ctsvm_fetch32(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            ctsvm_result result = ctsvm_to_stack(vm, rd, rs);
            if (result != ctsvm_success)
            {
                return result;
            }

            break;
        }
        case ctsvm_op_stosp64:
        {
            uint64_t rd = ctsvm_fetch64(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            ctsvm_result result = ctsvm_to_stack(vm, rd, rs);
            if (result != ctsvm_success)
            {
                return result;
            }

            break;
        }
        case ctsvm_op_lodsp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            int64_t rs = (int32_t)ctsvm_fetch32(vm);
            
            vm->reg[rd] = ctsvm_from_stack(vm, rs);

            break;
        }
        case ctsvm_op_addsp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            vm->sp += vm->reg[rd];

            if ((uintptr_t)vm->sp > STACK_TOP)
            {
                return ctsvm_access_violation;
            }

            break;
        }
        case ctsvm_op_addsp32:
        {
            uint32_t rd = ctsvm_fetch32(vm);
            
            vm->sp += rd;
            
            if ((uintptr_t)vm->sp > STACK_TOP)
            {
                return ctsvm_access_violation;
            }

            break;
        }
        case ctsvm_op_subsp:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            
            vm->sp -= vm->reg[rd];

            if ((uintptr_t)vm->sp < STACK_BOTTOM)
            {
                return ctsvm_access_violation;
            }

            break;
        }
        case ctsvm_op_subsp32:
        {
            uint32_t rd = ctsvm_fetch32(vm);
            
            vm->sp -= rd;
            
            if ((uintptr_t)vm->sp < STACK_BOTTOM)
            {
                return ctsvm_access_violation;
            }

            break;
        }

        case ctsvm_op_add:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] += vm->reg[rs];

            break;
        }
        case ctsvm_op_add8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] += ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_add16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] += ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_add32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] += ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_add64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] += ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_sub:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] -= vm->reg[rs];

            break;
        }
        case ctsvm_op_sub8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] -= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_sub16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] -= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_sub32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] -= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_sub64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] -= ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_mul:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] *= vm->reg[rs];

            break;
        }
        case ctsvm_op_mul8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] *= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_mul16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] *= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_mul32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] *= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_mul64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] *= ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_div:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] /= vm->reg[rs];

            break;
        }
        case ctsvm_op_div8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] /= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_div16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] /= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_div32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] /= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_div64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] /= ctsvm_fetch64(vm);

            break;
        }

        case ctsvm_op_and:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] &= vm->reg[rs];

            break;
        }
        case ctsvm_op_and8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] &= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_and16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] &= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_and32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] &= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_and64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] &= ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_or:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] |= vm->reg[rs];

            break;
        }
        case ctsvm_op_or8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] |= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_or16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] |= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_or32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] |= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_or64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] |= ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_xor:
        {
            uint8_t rd = ctsvm_fetch8(vm);
            uint8_t rs = ctsvm_fetch8(vm);

            vm->reg[rd] ^= vm->reg[rs];

            break;
        }
        case ctsvm_op_xor8:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] ^= ctsvm_fetch8(vm);

            break;
        }
        case ctsvm_op_xor16:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] ^= ctsvm_fetch16(vm);

            break;
        }
        case ctsvm_op_xor32:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] ^= ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_xor64:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] ^= ctsvm_fetch64(vm);

            break;
        }
        case ctsvm_op_not:
        {
            uint8_t rd = ctsvm_fetch8(vm);

            vm->reg[rd] = ~vm->reg[rd];

            break;
        }

        case ctsvm_op_jmp:
        {
            vm->ip += (int32_t)ctsvm_fetch32(vm);

            break;
        }
        case ctsvm_op_je:
        {
            vm->ip += (vm->cmp == 0) ? (int32_t)ctsvm_fetch32(vm) : 4;

            break;
        }
        case ctsvm_op_jne:
        {
            vm->ip += (vm->cmp != 0) ? (int32_t)ctsvm_fetch32(vm) : 4;

            break;
        }
        case ctsvm_op_jl:
        {
            vm->ip += (vm->cmp < 0) ? (int32_t)ctsvm_fetch32(vm) : 4;

            break;
        }
        case ctsvm_op_jg:
        {
            vm->ip += (vm->cmp > 0) ? (int32_t)ctsvm_fetch32(vm) : 4;

            break;
        }
    }
    
    return ctsvm_success;
}

ctsvm_state *ctsvm_create_state(void)
{
    ctsvm_state *vm = calloc(1, sizeof(ctsvm_state));
    if (!vm)
    {
        return NULL;
    }

    vm->stack_max = (uintptr_t)vm->ram + STACK_TOP;
    vm->stack_min = (uintptr_t)vm->ram + STACK_BOTTOM;

    return vm;
}

void ctsvm_destroy_state(ctsvm_state *vm)
{
    if (vm)
    {
        free(vm);
    }
}

void ctsvm_dump_state(ctsvm_state *vm)
{
    if (vm)
    {
        for (int i = 0; i < REG_COUNT / 8; i++)
        {
            printf("R%d: %lld\n", i, vm->reg[i]);
        }
    }
}

ctsvm_result ctsvm_load(ctsvm_state *vm, const uint8_t *bytes, size_t size)
{
    if (!vm || !bytes || size > RAMBLOCK_SIZE) 
    {
        return ctsvm_invalid_arg;
    }
    
    vm->sp = vm->ram + STACK_TOP;
    vm->ip = vm->ram + RAMBLOCK_PTR;
    memcpy(vm->ip, bytes, size);
    
    return ctsvm_success;
}

ctsvm_result ctsvm_run(ctsvm_state *vm)
{
    if (!vm || !vm->ram || !vm->sp || !vm->ip) 
    {
        return ctsvm_invalid_arg;
    }
    
    size_t i = 0;
    ctsvm_result result = ctsvm_success;
    while (result == ctsvm_success && i++ < MAX_CYCLES)
    {
        result = ctsvm_step(vm);
    }
    
    return result;
}
#include "include/ctsvm.h"

#include <string.h>
#include <stdio.h>

static uint8_t code[] = {
   ctsvm_op_leaip8, 0, 2,
   ctsvm_op_ccall, 0,
   ctsvm_op_halt,
   
   0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00
};

ctsvm_result print_str(ctsvm_state *vm)
{
    uintptr_t ptr = vm->reg[0];

    printf("%s\n", &vm->ram[ptr]);

    return ctsvm_success;
}

int main(int argc, char *argv[])
{
    ctsvm_state *vm = ctsvm_create_state();
    if (!vm)
    {
        puts("Failed to create state.");
        return 1;
    }

    ctsvm_load(vm, code, sizeof(code));
    ctsvm_push_closure(vm, print_str);

    ctsvm_run(vm);

    ctsvm_destroy_state(vm);
    return 0;
}
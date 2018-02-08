#!/bin/bash
echo Build the object code
arm-none-eabi-as -EL -o build/printf.o src/printf.s

echo running the linker
arm-none-eabi-ld build/printf.o -o release/printf.bin -Ttext-segment 0x00000000 -s --gc-sections 

arm-none-eabi-objcopy -O binary release/printf.bin 


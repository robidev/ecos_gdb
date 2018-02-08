#!/bin/bash
echo Build the object code
arm-none-eabi-as -EL -o jump.o src/jump.s

echo running the linker
arm-none-eabi-ld jump.o -o jump.bin -Ttext-segment 0x00000000 
rm jump.o

arm-none-eabi-objcopy -O binary jump.bin 

echo disassembling the binary
arm-none-eabi-objdump -d  --section=.data -b binary -marm jump.bin  > release/jump.txt
rm jump.bin 

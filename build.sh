#!/bin/bash
echo Build the object code
arm-none-eabi-as -EL -o build/code.o src/serial.s

echo running the linker
arm-none-eabi-ld build/code.o -o release/code.bin -Ttext-segment 0x00000000 -s --gc-sections 

arm-none-eabi-objcopy -O binary release/code.bin 

echo strip the first bytes 
# 1164180 (0x0011c394 ), so we are left with just the gdb code
split --bytes=1164180 release/code.bin release/code.part_
rm release/code.part_aa
rm release/gdb
mv release/code.part_ab release/gdb



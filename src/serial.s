@@@@ finetune @@@@
@@ PC_addr		= -0x04
@@ const_vars	= 0x0C
@@@@@@@@@@@@@@@@@@

@@@@ Register asignment @@@@
@CSPR = used during cmp and such
@R15 = PC
@R14 = LR
@R13 = SP
@R12 = used in getc
@R11 = used in getc
@R10 = CSPR
@R9  = SP_origin
@R8  = return value
@R7  = instruction to write at breakpoint
@R6  = switch-case
@R5  = 
@R4  = 
@R3  = 
@R2  = work reg
@R1  = work reg
@R0  = work reg
@@@@@@@@@@@@@@@@@@@@@@@@@@@

.text
.org 	0x0005c1f4									@offset of function for cyg_io_read
cyg_io_read:	MOV				PC, LR	
.org 	0x000644C0 									@offset of print_text_uart, alternatives are kprintf_2():0x0005D01C, kprintf():0x0005D0A8
printf:			MOV				PC, LR
		
.global _start
.org 0x0011C394										@free space in binary, setting this will ensure BL offset is correct
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@            --main code--					  @@@
PC_addr		= 0x38									@top of stack + 15*4 bytes = 60
_start:	STMFD 			sp!, {R0-R12, LR ,PC}	@store registers on stack(also PC)
		MRS				R10, SPSR					@store SPSR
													@-breakpoint restore--
		MOV				R9, SP						@ load addr of heap in r9
		STMFD			sp!,{R9,R10}				@ store also SP and SPSR 
		LDR 			R0, =0xEB018769				@ load data from literal
		LDR 			R1, =0x00002714				@ load addr from literal
		STR 			R0, [R1]					@ store data to addr; restore instuction at breakpoint
		STR 			R1, [R9, #PC_addr]			@ load return addr in stack_PC, so overwrite the PC on the stack with the address it should return to
													@--debugger interface--
		MOV 			R8, #0						@return = 0
loop:	BL 				getc						@ selection of option: 
													@0=exit(),
													@1=read(addr),
													@2=write(addr,val),
													@3=read(reg),
													@4=write(reg,val),
													@5=breakpoint(addr,instr),
													@6=test()
		MOV 			R6, R0						@store selection into R6
		
		CMP 			R6, #'0'
		BEQ 			exit						@ exit the debugger, and resume program until next breakpoint

		CMP 			R6, #'1'
		BNE 			tst2 
		BL 				getw						@ memory address to read
		LDR				R1, [R0] 					@load memory at this location
		LDR 			R0, =string					
		BL 				printf						@ read memory, relative!!!!!
		
tst2:	CMP 			R6, #'2'
		BNE 			tst3
		BL 				getw						@ memory address to write
		MOV				R2, R0						@ and store in R2
		BL 				getw						@ memory value to write		
		STR 			R0, [R2]					@ write memory
		
tst3:	CMP 			R6, #'3' 
		BNE 			tst4
		BL 				getc						@ register index to print
		LSL				R0, #2		
		ADD 			R2, R0, R9					@ multiply the register-number by 4, and add to R9  
		LDR 			R1, [R2, #-8]               @ offset of stack -2, for cspr and SP
		LDR 			R0, =string
		BL 				printf						@ read registers on stack, relative!!!!!
		
tst4:	CMP 			R6, #'4' 
		BNE 			tst5
		BL 				getc						@ register intex to write
		LSL				R0, #2
		ADD 			R2, R9, R0		 			@ multiply the register-number by 4, and add to R9
		BL 				getw						@ value to write
		STR 			R0, [R2, #-8]				@ write registers on stack ( offset-2, for CSPR and SP)
		
tst5:	CMP 			R6, #'5' 
		BNE 			tst6
		BL 				getw						@ get breakpoint address from input
		STR 			R0, [PC,#0xC0]				@ store breakpoint in addr
		BL 				getw						@ get instruction from input
		MOV 			R7, R0						@ the new instruction, that contains: ((((PC-8) - R1)/4 + 2) | 0xEB000000); relative branch from addr to this code(PC-8), ensure to write it little-endian
		MOV 			R8, #1 
		
tst6:	CMP 			R6, #'6' 
		BNE 			loop
		LDR 			R0, =tst
		BL 				printf 						@ test/reset the interface, relative!!!!!
		B 				loop						@loop forever until exit is selected
		
exit:	CMP 			R8, #0						@ check if we need to patch an new instruction
		BLEQ 			nopatch 					@ jump over the patcher

													@--set new breakpoint--
		LDR 			R0, =0x00002714				@ load new addr,
		LDR 			R1, [R0]					@ load instruction from the addr where we intend to set the breakpoint in R1
		STR 			R1, [PC,#0x88]				@ store the original instruction in data, so it can be restored
		STR 			R7, [R0]					@ patch the instruction with the breakpoint at the new address, R0 was allready loaded with the right address, R7 contained the instruction, from when we set it, above

nopatch:											@ --return to program--
		LDMFD			sp!,{R9,R10}				@ restore also SP and SPSR 
		MOV				SP, R9						@ modify SP, if desired
		MSR 			CPSR_cf, R10				@ restore CPSR
		LDMFD 			SP!, {R0-R12, LR, PC}		@ restore registers on stack, and jump out of routine 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
@@@ --- int getc(), returns 1 character ---       @@@
len             = -0x28
buffer          = -0x21
getc:   MOV             R12, SP
        STMFD           SP!, {R1-R8,R11,R12,LR,PC}
        SUB             R11, R12, #4
        SUB             SP, SP, #8
        MOV             R7, #0
        MOV             R3, #1
        STRB            R7, [R11,#buffer]
        STR             R3, [R11,#len]
        SUB             R6, R11, #-buffer
        SUB             R5, R11, #-len
loop_char:                                			@ CODE XREF: getline_uart
        LDR             R3, =0x13A6C4
        MOV             R1, R6
        LDR             R0, [R3]
        MOV             R2, R5
        BL              cyg_io_read					@ relative!!!!!
        CMP             R0, #0
        BNE             loop_char
        LDRB            R2, [R11,#buffer]
        AND             R0, R2, #0xFF
        LDMDB           R11, {R1-R8,R11,SP,PC}
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@		
getw:	stmfd			SP!,{r2, lr}
		BL 				getc						@ memory value to write
		LSL				R1, R0, #0x18				@ shift 24 bits
		BL 				getc						@ 	
		ORR				R1, R0, LSL	#0x10			@ shift 16 bits			
		BL 				getc						@ 	
		ORR				R1, R0, LSL	#0x08			@ shift 8 bits	
		BL 				getc						@ 	
		ORR				R0, R0, R1					@ shift 8 bits	, and store in R0		
		ldmfd			sp!,{r2, PC}
		
.ltorg												@literal pool for data used in main
@data    = 0xEB010101								@variable to hold data at breakpoint
@addres  = 0xFFFF2714								@variable to hold address of breakpoint
@string  -> "%08x\n"								@string to be printed, with data in R1 in hex
@tst     -> "tst\n"									@test-string
@getc_c  = 0x0013A6C4								@address of call to cyg_io_read dma-ish buffer

string:	.asciz	"%08x\n"
tst:	.asciz	"tst\n"
.end





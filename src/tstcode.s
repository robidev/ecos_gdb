.text
.org 	0x0005c1f4									@offset of function for cyg_io_read
cyg_io_read:		
.org 	0x000644C0 									@offset of printf
printf:			
		
.global _start
.org 0x0011C394										@free space in binary, setting this will ensure BL offset is correct
@@@            --main code--					  @@@
_start:	STMFD 			sp!, {R0-R12, LR ,PC}	@store registers on stack(also PC)
loop:	BL 				getc						@ selection of option: 
													@0=exit(),
													@6=test()
		MOV 			R6, R0						@store selection into R6
		
		CMP 			R6, #'0'
		BEQ 			exit						@ exit the debugger, and resume program until next breakpoint

tst6:	CMP 			R6, #'6' 
		BNE 			loop
		LDR 			R0, =tst
		BL 				printf 						@ test/reset the interface,
		B 				loop						@loop forever until exit is selected
		
exit:   LDMFD 			SP!, {R0-R12, LR, PC}		@ restore registers on stack, and jump out of routine 
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


tst:	.asciz	"tst\n"
.end





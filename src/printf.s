.text
.global _start
.org 0x00000000
_start:		STMFD	SP!,{ LR}			@store link register to return
			ADD		R0, PC, #8			@position independent way to address string
			MOV 	LR, PC	 		    @store link register for printf to return to(PC+8)
			LDR		PC, =0x000644C0		@addresss of printf
		    LDMFD	SP!,{ PC}
string:		.asciz "Register R1: %08x\n"
.end

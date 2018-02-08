.text
.org    0x00068df8                                  @close
close:          MOV				PC, LR      
.org 	0x00069b90									@socket
socket:	        MOV				PC, LR	
.org 	0x00069ed0 									@connect
connect:		MOV				PC, LR
.org 	0x0006a2a8									@recv
recv:	        MOV				PC, LR	
.org 	0x0006a3c0 									@send
send:			MOV				PC, LR
			
	
.global _start
.org 0x0011C000	

PC_addr		= 0x38									        @top of stack + 15*4 bytes = 60
_start:	        STMFD 			sp!, {R0-R12, LR ,PC}	    @store registers on stack(also PC)
                MRS				R10, SPSR					@store SPSR
                                                            @-breakpoint restore--
                MOV				R9, SP						@ load addr of heap in r9
                STMFD			sp!,{R9,R10}				@ store also SP and SPSR 
                LDR 			R0, =0xEB018769				@ load data from literal
                LDR 			R1, =0x00002714				@ load addr from literal
                STR 			R0, [R1]					@ store data to addr; restore instuction at breakpoint
                STR 			R1, [R9, #PC_addr]			@ load return addr in stack_PC, so overwrite the PC on the stack with the address it should return to

                add	            R11, sp, #4
                sub	            sp, sp, #64
                sub	            r3, R11, #36
                
                mov	            r2, #0
                str	            r2, [r3]                    @store 0000 in buf2 

                mov	            r3, #10
                strb	        r3, [R11, #-32]              @store /n in buf2
                
                MOV             R3, #2
                STRB            R3, [R11,#-67]              @ store family=AF_INET 
                
                LDR             R3, =0xA10Fa10f
                STRH            R3, [R11,#-66]              @ store port=4001      
                
                LDR             R3, =0x057FA8C0
                STR             R3, [R11,#-64]              @ store IP=192.168.32.39
                
                MOV             R3, #32 ;
                STRB            R3, [R11,#-68]              @ store len             
                
                MOV             R2, #6
                MOV             R1, #1
                MOV             R0, #2
                BL              socket                      @ open tcp socket, ret=r0
                STR             R0, [R11,#-8]               @ store socket on stack (r11-8)
               
                SUB             R1, R11, #68
                MOV             R2, #32
                LDR             R0, [R11,#-8]               @ get socket on stack (r11-8)
                BL              connect                     @ connect to port using struct
                STR             R0, [R11,#-12 ]             @ store connect result on stack (r11-12)

                MOV             R8,#0

loop:           SUB             R1, R11, #28                @ buf
                MOV             R3, #0
                MOV             R2, #12
                LDR             R0, [R11,#-8]               @ get socket on stack (r11-8)
                BL              recv                        @ recv max 9 bytes
                CMP             R0, #0                  
                BLE             loop                        @ if nothing received, try again
                LDR             R6, [R11,#-28]              @ get first byte from buffer (R11 -28)

                CMP 			R6, #'0'
                ldreq           r0, [R11, #-8]
                bleq            close                       @close the socket  
                BEQ 			exit						@ exit the debugger, and resume program until next breakpoint

                CMP 			R6, #'1'
                BNE 			tst2 
                LDR 			R0, [R11,#-24]	            @ memory address to read buf[1]
                LDR				R1, [R0] 					@load memory at this location
                BL 				send_int					@ send data in R1
		
tst2:	        CMP 			R6, #'2'
                BNE 			tst3
                LDR 			R2, [R11, #-24]				@ memory address to write
                LDR 			R0, [R11, #-20]				@ memory value to write	
                STR 			R0, [R2]					@ write memory
		
tst3:	        CMP 			R6, #'3' 
                BNE 			tst4
                LDR 			R0, [R11, #-24]				@ register index to print
                LSL				R0, #2		
                ADD 			R2, R0, R9					@ multiply the register-number by 4, and add to R9  
                LDR 			R1, [R2, #-8]               @ offset of stack -2, for cspr and SP
                BL 				send_int					@ send data in R1
		
tst4:	        CMP 			R6, #'4' 
                BNE 			tst5
                LDR 			R0, [R11, #-24]				@ register intex to write
                LSL				R0, #2
                ADD 			R2, R9, R0		 			@ multiply the register-number by 4, and add to R9
		        LDR 			R0, [R11, #-20]				@ value to write
                STR 			R0, [R2, #-8]				@ write registers on stack ( offset-2, for CSPR and SP)
		
tst5:	        CMP 			R6, #'5' 
                BNE 			tst6
		        LDR 			R0, [R11, #-24]				@ get breakpoint address from input
                STR 			R0, [PC,#0x68]				@ TODO store breakpoint-addr in addr
                LDR 			R0, [R11, #-20]				@ get instruction from input
                MOV 			R7, R0						@ the new instruction, that contains: ((((PC-8) - R1)/4 + 2) | 0xEB000000); relative branch from addr to this code(PC-8)
                MOV 			R8, #1 
		
tst6:	        CMP 			R6, #'6' 
                BNE 			loop
                LDR 			R1, =0x20545354
                BL 				send_int					@ send data in R1
                B 				loop						@loop forever until exit is selected
                
exit:	        CMP 			R8, #0						@ check if we need to patch an new instruction
                BLEQ 			nopatch 					@ jump over the patcher

                                                            @--set new breakpoint--
                LDR 			R0, =0x00002714				@ load new addr,
                LDR 			R1, [R0]					@ load instruction from the addr where we intend to set the breakpoint in R1
                STR 			R1, [PC,#0x30]				@ TODO store the original instruction in data, so it can be restored
                STR 			R7, [R0]					@ patch the instruction with the breakpoint at the new address, R0 was allready loaded with the right address, R7 contained the instruction, from when we set it, above

nopatch:		add	            sp, sp, #64					@ --return to program--
                LDMFD			sp!,{R9,R10}				@ restore also SP and SPSR 
                MOV				SP, R9						@ modify SP, if desired
                MSR 			CPSR_cf, R10				@ restore CPSR
                LDMFD 			SP!, {R0-R12, LR, PC}		@ restore registers on stack, and jump out of routine 
@*************************************************
@r1 as data
send_int:       STMFD			SP!,{R11, LR}			@store link register to return
		        str             R1, [R11,#-36]               @ store register in buffer2 to send
                sub             R1, R11, #36                 @ load buffer-address in r1
                MOV             R3, #0
                MOV             R2, #5
                LDR             R0, [R11,#-8]
                BL              send
		    	LDMFD			SP!,{R11, PC}
@*************************************************
.ltorg
.end

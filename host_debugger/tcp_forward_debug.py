#!/usr/bin/env python
from capstone import *
from keystone import *

import subprocess as sp
import sys
import time
import socket
import struct
import threading

__author__  = "robin"
__email__   = "..."
__version__ = "1.0.0"
__date__    = "01AUG2017"
"""
TODO:
"""

#tweak this value to speed up the interface
SYNC_RETRIES = 10    #retries when trying to sync
SLEEP_TIME = 0.01    #sleep period after a read or write, to allow the debugged device to parse the data

#this is where the debugger entry point resides, it is used to calculate the jump when setting a breakpoint
GDB_ADDR = 0x0011c000
#GDB_ADDR = 0x0011c394

#register definitions
PC = 16
LR = 15
SP = 0
CSPR = 1
PC_addr		= 0x3c # offset for SP, as it is stored after the initial push

#helper class for the serial functions
def to_bytes(seq):
    """convert a sequence to a bytes type"""
    if isinstance(seq, bytes):
        return seq
    elif isinstance(seq, bytearray):
        return bytes(seq)
    elif isinstance(seq, memoryview):
        return seq.tobytes()
    elif isinstance(seq, unicode):
        raise TypeError('unicode strings are not supported, please encode to bytes: {!r}'.format(seq))
    else:
        # handle list of integers and bytes (one or more items) for Python 2 and 3
        return bytes(bytearray(seq))


#function to stop the debugger, and continue normal program execution
def stop():
    packet = bytearray()    
    packet += struct.pack("<I", 0x30 )
    tcp_write(packet)
    conn.close()

#function to write the data to the serial port using delays for the debugger to parse the data
def tcp_write(data):
    d = to_bytes(data)
    conn.send(d) # should be 1 byte option, 4 or 8 bytes of data


#function to read the data, and providing time for the debugger
def tcp_read():
    read = bytearray()
    read = conn.recv(5) # should be 4 bytes of data, and 0x10
        
    if len(read) != 5 or read[4] != '\n':
        print "get_mem: error receiving data: %s" % (read) 
        return bytes("DEAD")
    else:
        return bytes(read[0:4])
    

#function to retrieve 4 bytes of memory from the device at ADDRESS
def get_mem(ADDRESS):
    packet = bytearray()
    packet += struct.pack("<I", 0x31 )
    packet += struct.pack("<I", ADDRESS )
    tcp_write(packet)
    return tcp_read()

#function to write VALUE at ADDRESS in the device memory
def set_mem(ADDRESS,VALUE):
    packet = bytearray()
    packet += struct.pack("<I", 0x32 )
    packet += struct.pack("<I", ADDRESS )
    packet += struct.pack("<I", VALUE )
    tcp_write(packet)

#function to read REGISTER in the device {0=SP, 1=CSPR, 2=R0, .. 14=R12, 15=LR, 16=PC}
def get_register(REGISTER):
    packet = bytearray()
    packet += struct.pack("<I", 0x33)
    packet += struct.pack('<I', REGISTER)
    tcp_write(packet)
    VALUE = struct.unpack('<I',tcp_read())[0]
    if REGISTER == 0:    #if register is SP, add PC_addr, to accomodate sp offset
        VALUE += PC_addr
    return VALUE

#function to write VALUE in REGISTER
def set_register(REGISTER,VALUE):
    if REGISTER == 0:    #if register is SP, subtract PC_addr, to accomodate sp offset
        VALUE -= PC_addr
    packet = bytearray()
    packet += struct.pack("<I", 0x34 )
    packet += struct.pack('<I', REGISTER)
    packet += struct.pack("<I", VALUE)
    tcp_write(packet)

#function to set 1 new breakpoint in the code at ADDRESS, that will be hit after the debugger continues
#only 1 breakpoint is currently supported
def set_breakpoint(ADDRESS):
    # separate assembly instructions by ; or \n
    INSTRUCTION = 0xEA000001 #initial instruction, will be overwritten
    addr1 = "%.08X" % (ADDRESS)
    addr2 = "%.08X" % (GDB_ADDR)
    CODE_ASM = b''
    if addr2 > addr1: # org cannot go from a higher to a lower value, so ensure addresses are incremental
        CODE_ASM =  ('.org 0x'+addr1+'\n'
                'B jump\n'
                '.org 0x'+addr2+'\n'
                'jump:\n').encode() 
    else:
        CODE_ASM =  ('.org 0x'+addr2+'\n'
                'jump:\n'
                '.org 0x'+addr1+'\n'
                'B jump\n').encode() 
    #print ADDRESS    #print GDB_ADDR   print CODE_ASM
    try:
        # Initialize engine in ARM mode
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(CODE_ASM)
        jump_i = chr(encoding[ADDRESS+0])
        jump_i += chr(encoding[ADDRESS+1])
        jump_i += chr(encoding[ADDRESS+2])
        jump_i += chr(encoding[ADDRESS+3])
        jump_it = struct.unpack("I",jump_i)
        #print "%.08X" % jump_it[0]
        INSTRUCTION = jump_it[0]
    except KsError as e:
        print("ERROR: %s" %e)
    packet = bytearray()    
    packet += struct.pack("<I", 0x35 )
    packet += struct.pack("<I", ADDRESS ) 
    packet += struct.pack("<I", INSTRUCTION ) 
    tcp_write(packet)

#function to ensure the interface between the host and the debugged system is synchronised
# return -1 means failed, return 0 means succes
def resync_interface():
    global conn
    TIMEOUT = 0
    retry = 0
    while True:
        packet = bytearray()    
        packet += struct.pack("<I", 0x36 )
        try:
            tcp_write(packet)
            response = tcp_read() 
            if 'TST' in response:
            #tcp_read() #to be sure the buffer is empty
                break
            TIMEOUT += 1
            if TIMEOUT > SYNC_RETRIES:
                print "ERROR:could not sync"
                return -1
            time.sleep(1)
        except:
            print "EXCEPTION: cannot send/receive, restarting connection"
            while retry == 0:
                conn.close()
                try:
                    print "trying to reconnect..."
                    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    conn.connect((TCP_IP, port))
                    retry = 1
                    print "reconnect successfull, resuming resync"
                except:
                    print "EXCEPTION: cannot connect, retrying..."
                    TIMEOUT += 1
                    if TIMEOUT > SYNC_RETRIES:
                        print "ERROR:could not connect, giving up"
                        return -1
                time.sleep(1)
    return 0

#function to retrieve the code at PC_P, and return disassembled
def get_code(PC_P):
    INSTRUCTION = []
    P_INS_l = []
    CODE = b""
    md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
    code_pointer =PC_P-24
    if code_pointer < 0:
        code_pointer = 0
    for i in range (0, 20):
        mem_val = get_mem((code_pointer) + (i*4))
        CODE += mem_val
    for f in md.disasm(CODE,code_pointer, 20):
        INSTRUCTION.append("%.8X: %-12s %s %s" % (f.address,
                           "%08x" % (struct.unpack_from('I', f.bytes)),
                           f.mnemonic,
                           f.op_str))
    for i in range(0,20):
        if i < len(INSTRUCTION):
            P_INS_l.append(INSTRUCTION[i])
        else:
            P_INS_l.append("")
    return P_INS_l

#function to retrieve the stack data at ADDRESS
def get_stack(ADDRESS):
    STACK_l = []
    ADDRESS -= 0x0c
    if ADDRESS < 0:
        ADDRESS = 0
    for i in range(0,8):
        STACK_l.append("%.08X: %.08X" % (i*4+ADDRESS, struct.unpack('I',get_mem(i*4+ADDRESS))[0]))
    return STACK_l

#function to retrieve all registers
def get_registers():
    REGISTERS_l = []
    for i in range(0,17):
        REGISTERS_l.append( get_register(i) )
    cspr = get_register(CSPR)
    cspr_bin = "{0:032b}".format(cspr)
    return cspr_bin, REGISTERS_l

#function to retrieve a dump of the memory at DUMP_ADDRESS.
def get_dump(DUMP_ADDRESS):
    DUMP_LIST = []
    DUMP = []
    #print "calling with address: %d" % DUMP_ADDRESS
    for i in range(0,16):
        mem_val = get_mem((i*4) + DUMP_ADDRESS)
        DUMP_LIST += mem_val
    for i in range(0,8):
        BYTES = ""
        for j in range(0,8):
            BYTES += "%.02x " % (ord(DUMP_LIST[(i*8)+j]))
        ASCII = ""
        for x in DUMP_LIST[i*8:(i*8)+8]:
            x = ord(x)
            if x >= 33 and x <= 126:
                ASCII += chr(x)
            else:
                ASCII += "."
        DUMP.append("%.8X: %s| %s" % (DUMP_ADDRESS + (i*8), BYTES, ASCII))
    return DUMP

#write_shellcode 2714 /home/robin/Desktop/shellbug/test.py
def write_shellcode(addr, file_name):
    SEEK_END = 2
    file = open(file_name, "r") 
    file.seek(0, SEEK_END)      # retrieve file length
    file_length = file.tell()   #
    file.seek(0)                # reset file position
    residual = (file_length % 4)# check if file is aligned on 4 bytes
    if residual > 0:            # if not, add another 4 bytes
        residual = 4 - residual #
    ints = (file_length + residual) / 4 # divide by 4, as data is written per 4 bytes
    for i in range(0,ints):     # loop this many times to ensure the whole file is loaded
        data = 0x00000000       # init data to 0, in case the try fails
        try:                    
            d = file.read(4)    # read 4 bytes from the file
            while len(d) < 4:   # pad the data with 00 in case it is not 4 bytes long
                d = d + b'\x00' #  
            data = struct.unpack("I", bytearray(d))[0] #convert it to an int, so it can be written
        except Exception:       # ignore all exceptions
            pass
        print "%.08X,%.08X" % ((addr + (i * 4)), data) 
        set_mem(addr + (i * 4), data)

#write data in a patch file with the following format;"[ADDRESS IN HEX(int)] [DATA IN HEX(4 bytes)]\n"
def write_patch(file_name):
    list_addr_data = []
    #read the data from a file into an array
    file = open(file_name, "r")
    for line in file.readlines():
        list_addr_data = line.split(" ")
        addr = parse_number( list_addr_data[0] ) #convert from little to big endian
        data = struct.unpack("I", struct.pack(">I", parse_number( list_addr_data[1] ) ) )[0]#convert from little to big endian
        print "%.08X,%.08X" % (addr, data) 
        set_mem(addr, data)        


def run_shellcode(addr):
    #write PC to addr
    set_register(PC, addr) 
    #write LR to 0x0011c394
    set_register(LR, GDB_ADDR)
    #stop the debugger, and run the shellcode
    stop()
    
#this instruction allows any piece of code to be patched without affecting the original code,
#it will patch an instruction with a branch, call the code provided in 'file_name', and patch the
#original instruction back. finally, it will jump back to the original code, and resume execution
#arguments are: 
#   patch_addr      - address of code to be patched
#   code_addr       - address where code should be placed
#   file_name       - file with the code to be written
def code_patcher(patch_addr, code_addr, file_name):
    ORIGINAL_INSTR = 0xEA000001 #initial instruction, will be overwritten
    addr1 = "%.08X" % (patch_addr)
    addr2 = "%.08X" % (code_addr)
    encoding = []
    #create patcher

    ORIGINAL_INSTR = "%.08X" % (struct.unpack('I',get_mem(patch_addr))[0])  # retrieve instruction to be patched
    CODE_ASM =  ('.org 0x00000000                               \n'
                '           STMFD   SP!, {r0-r12,LR}            \n'    #store all data
                '           LDR     R0, =0x'+ORIGINAL_INSTR+'   \n'    #load instruction from ltorg(literal pool)
                '           LDR     R1, =0x'+addr1+'            \n'    #load original instruction address
                '           STR     R0, [R1]                    \n'    #restore original instruction
                '           BL      0x00000028                  \n'    #branch(and link) to our shellcode
                '           LDMFD   SP!, {r0-r12,LR}            \n'    #restore stack and return
                '           LDR     PC, =0x'+addr1+'            \n'    #return address(code addr)
                '.ltorg                                         \n'    #store literal pool here (8 bytes)
                'func:      MOV R0,R1                           \n').encode()      #jump to shellcode (offset should be 32 bytes)
    try:
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)   # Initialize engine in ARM mode
        encoding, count = ks.asm(CODE_ASM)
    except KsError as e:
        print("ERROR: %s" %e)    
    
    for i in range(0,40,4): # write encoded bytes to mem (should be 32 bytes)
        data = chr(encoding[i+0])
        data += chr(encoding[i+1])
        data += chr(encoding[i+2])
        data += chr(encoding[i+3])
        data_b = struct.unpack("I",data)[0]
        set_mem(code_addr + i, data_b)
    
    write_shellcode(code_addr + 0x28, file_name)              # write the shellcode into memory, behind the patcher
    
    
    #calculate jump to the patcher
    if addr2 > addr1: # org cannot go from a higher to a lower value, so ensure addresses are incremental
        CODE_ASM =  ('.org 0x'+addr1+'\n'
                'B jump\n'
                '.org 0x'+addr2+'\n'
                'jump:\n').encode() 
    else:
        CODE_ASM =  ('.org 0x'+addr2+'\n'
                'jump:\n'
                '.org 0x'+addr1+'\n'
                'B jump\n').encode() 
    try:
        # Initialize engine in ARM mode
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(CODE_ASM)
    except KsError as e:
        print("ERROR: %s" %e)
        
    jump_i = chr(encoding[patch_addr+0])
    jump_i += chr(encoding[patch_addr+1])
    jump_i += chr(encoding[patch_addr+2])
    jump_i += chr(encoding[patch_addr+3])
    jump_it = struct.unpack("I",jump_i)[0]
    set_mem(patch_addr, jump_it)                        # patch memory with instruction to our code
    
#function to print the console
def print_console(MESSAGE, P_INS, DUMP, STACK, FLAGS, REGISTERS):
    tmp = sp.call('clear', shell=True)
    print "+" + "-" * 62 + "+" + "-" * 16 + "+"
    print "|   %-58s | R00: %.08X %1s|" % (P_INS[0], REGISTERS[2], "") # 
    print "|   %-58s | R01: %.08X %1s|" % (P_INS[1], REGISTERS[3], "") # 
    print "|   %-58s | R02: %.08X %1s|" % (P_INS[2], REGISTERS[4], "") # 
    print "|   %-58s | R03: %.08X %1s|" % (P_INS[3], REGISTERS[5], "") # 
    print "|   %-58s | R04: %.08X %1s|" % (P_INS[4], REGISTERS[6], "") # 
    print "|   %-58s | R05: %.08X %1s|" % (P_INS[5], REGISTERS[7], "") # 
    print "|\x1b[6;1;37;41m >>%-58s \x1b[0m| R06: %.08X %1s|" % (P_INS[6], REGISTERS[8], "") # 
    print "|   %-58s | R07: %.08X %1s|" % (P_INS[7], REGISTERS[9], "") # 
    print "|   %-58s | R08: %.08X %1s|" % (P_INS[8], REGISTERS[10], "")
    print "|   %-58s | R09: %.08X %1s|" % (P_INS[9], REGISTERS[11], "")
    print "|   %-58s | R10: %.08X %1s|" % (P_INS[10], REGISTERS[12], "")
    print "|   %-58s | R11: %.08X %1s|" % (P_INS[11], REGISTERS[13], "")
    print "|   %-58s | R12: %.08X %1s|" % (P_INS[12], REGISTERS[14], "")
    print "|   %-58s | SP : %.08X %1s|" % (P_INS[13], REGISTERS[0], "")
    print "|   %-58s | LR : %.08X %1s|" % (P_INS[14], REGISTERS[15], "")
    print "|   %-58s | PC : %.08X %1s|" % (P_INS[15], REGISTERS[16], "")
    print "|   %-58s | N: %s Z: %s %5s|" % (P_INS[16], FLAGS[-1], FLAGS[-2], "")
    print "|   %-58s | C: %s V: %s %5s|" % (P_INS[17], FLAGS[-3], FLAGS[-4], "")
    print "|   %-58s | Q: %s 1: %s %5s|" % (P_INS[18], FLAGS[-5], FLAGS[-11], "")
    print "|   %-58s | J: %s 2: %s %5s|" % (P_INS[19], FLAGS[-7], FLAGS[-12], "")
    print "+" + "-" * 79 + "+"
    print "| %-76s %1s|" % (MESSAGE, "")
    print "+" + "-" * 79 + "+"
    print "|   %s %8s|   %-19s|" % (DUMP[0], "", STACK[0])
    print "|   %s %8s|   %-19s|" % (DUMP[1], "", STACK[1])
    print "|   %s %8s|   %-19s|" % (DUMP[2], "", STACK[2])
    print "|   %s %8s|\x1b[6;1;37;41m >>%-19s\x1b[0m|" % (DUMP[3], "", STACK[3])
    print "|   %s %8s|   %-19s|" % (DUMP[4], "", STACK[4])
    print "|   %s %8s|   %-19s|" % (DUMP[5], "", STACK[5])
    print "|   %s %8s|   %-19s|" % (DUMP[6], "", STACK[6])
    print "|   %s %8s|   %-19s|" % (DUMP[7], "", STACK[7])
    print "+" + "-" * 79 + "+"

#parse a string, and convert into an int
def parse_number( arg ):
    try:
        addr = int(arg,16)
        return addr
    except ValueError:
        print "ERROR: invalid number, please enter 8 digit hex number like; 000027EB"
    return -1

#MAIN
port = 4001
if len(sys.argv) > 1: # assign argument to port
    port = sys.argv[1]

REFRESH = True
DUMP_ADDRESS = 0x00000000
LAST_COMMAND = ""
MESSAGE = ""
DUMP = []
STACK = []
P_INS = []
FLAGS = []
REGISTERS = []

for i in range(0,30):
    DUMP.append("")
    FLAGS.append("0")
    REGISTERS.append("")
    P_INS.append("")
    STACK.append("")


TCP_IP = '192.168.127.254'
BUFFER_SIZE = 20  # Normally 1024, but we want fast response
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((TCP_IP, port))

print "syncing device"
# this ensures the device buffers on host and client are properly synced
if resync_interface() == -1:
    print "ERROR: cannot sync with the device"
    conn.close()
    sys.exit(1)
  
        
while True:
    
    if REFRESH == True:
        if resync_interface() == -1:
            sys.exit(1)
        
        #print "getting registers"
        FLAGS, REGISTERS = get_registers()
        
        #print "getting dump"
        DUMP = get_dump(DUMP_ADDRESS)
        
        SP_offset = REGISTERS[SP]
        #print "getting stack @ %d" % (SP_offset)
        STACK = get_stack(SP_offset)
        
        PC_offset = REGISTERS[PC]
        #print "getting code @ %d" % (PC_offset)
        P_INS = get_code(PC_offset)
        REFRESH = False
    
    # Print the console
    print_console(MESSAGE, P_INS, DUMP, STACK, FLAGS, REGISTERS)
    
    if LAST_COMMAND == "":
        COMMAND = raw_input("#[ ]> ")
    else:
        COMMAND = raw_input("#[%s]> " % LAST_COMMAND)

    if COMMAND == "":
        COMMAND = LAST_COMMAND

    COMMAND = COMMAND.split(' ')
    
    # rmem
    if COMMAND[0] == "m":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                result = struct.unpack('<I',get_mem( addr ))[0]
                MESSAGE = "get_mem %.08X : %.08X" % (addr, result)
        else:
            MESSAGE = "read memory usage: m [ADDRESS]"
        LAST_COMMAND = "read (m)emory"
        REFRESH = False
    
    # wmem
    if COMMAND[0] == "w":
        if len(COMMAND) > 2:
            addr = parse_number(COMMAND[1])
            val = parse_number(COMMAND[2])
            if addr >= 0 and val >= 0:
                set_mem(addr, val)
                MESSAGE = "set_mem %.08X : %.08X" % (addr, val)
        else:
            MESSAGE = "write memory usage: w [ADDRESS] [VALUE]"
        LAST_COMMAND = "(w)rite memory"
        REFRESH = False
        LAST_COMMAND = "n"
    
    # rreg
    if COMMAND[0] == "r":
        LAST_COMMAND = "r"
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                result = get_register( addr )
                MESSAGE = "get_reg %.08X : %.08X" % (addr, result)
        else:
            MESSAGE = "read register usage: r [REG](in hex!)"
        LAST_COMMAND = "read (r)egister"
        REFRESH = False
    
    # wreg
    if COMMAND[0] == "e":
        if len(COMMAND) > 2:
            addr = parse_number(COMMAND[1])
            val = parse_number(COMMAND[2])
            if addr >= 0 and val >= 0:
                set_register(addr,val)
                MESSAGE = "set_reg %.08X : %.08X" % (addr, val)
        else:
            MESSAGE = "write reg usage: e [REG] [VALUE](in hex!)"
        LAST_COMMAND = "(e) write register"
        REFRESH = False
        LAST_COMMAND = "e"
    
    # breakpoint
    if COMMAND[0] == "b":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                set_breakpoint(addr)
                MESSAGE = "breakpoint @ %.08X" % (addr)
        else:
            MESSAGE = "breakpoint usage: b [ADDRESS]"
        LAST_COMMAND = "(b)reakpoint"
        REFRESH = False
    
    # continue
    if COMMAND[0] == "c":
        stop()
        time.sleep(1) # wait a bit to allow the program to continue
        REFRESH = True
        LAST_COMMAND = "(c)ontinue"
        
    # step
    if COMMAND[0] == "s":
        addr = REGISTERS[PC]
        set_breakpoint(addr + 4)
        stop()
        time.sleep(1) # wait a bit to allow the program to continue
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((TCP_IP, port))
        REFRESH = True
        LAST_COMMAND = "(s)tep"
    
    # Print commands
    if COMMAND[0] == "?" or COMMAND[0] == "help":
        MESSAGE = "(q)uit | read (m)em | (w)rite mem | read (r)eg| | (e)write reg | (b)reakpoint | (c)ontinue |(s)tep | (y)refresh"
    
    # Refresh
    if COMMAND[0] == "y":
        REFRESH = True
        LAST_COMMAND = "(y) refresh"
    
    # Quit
    if COMMAND[0] == "q":
        conn.close()
        sys.exit(1)
    
    #write shellcode into memory
    if COMMAND[0] == "write_shellcode":
        if len(COMMAND) > 2:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                write_shellcode(addr, COMMAND[2])
        else:
            MESSAGE = "write shellcode usage: write_shellcode [ADDRESS] [SHELLCODE_FILE]"
        LAST_COMMAND = "(write_shellcode)"
        REFRESH = False
    
    #write patch into memory
    if COMMAND[0] == "write_patch":
        if len(COMMAND) > 1:
            write_patch(COMMAND[1])
        else:
            MESSAGE = "write patch usage: write_patch [SHELLCODE_FILE]"
        LAST_COMMAND = "(write_patch)"
        REFRESH = False
     
    #run shellcode from memory
    if COMMAND[0] == "run_shellcode":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                run_shellcode(addr)
        else:
            MESSAGE = "run shellcode usage: run_shellcode [ADDRESS]"
        LAST_COMMAND = "(run_shellcode)"
        REFRESH = True

    #patch code with shellcode from a file
    if COMMAND[0] == "code_patcher":
        if len(COMMAND) > 2:
            addr = parse_number(COMMAND[1])
            val = parse_number(COMMAND[2])
            if addr >= 0 and val >= 0:
                code_patcher(addr, val, COMMAND[3])
        else:
            MESSAGE = "code_patcher usage: code_patcher [PATCH_ADDRESS] [CODE_ADDRESS] [SHELLCODE_FILE]"
        LAST_COMMAND = "(code_patcher)"
        REFRESH = False
    
    
    #change dump address
    if COMMAND[0] == "dump":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                DUMP_ADDRESS = addr
                DUMP = get_dump(DUMP_ADDRESS)
        else:
            MESSAGE = "dump usage: dump [OFFSET]"
        LAST_COMMAND = "(dump)"
        REFRESH = False
        
    #change dump address down
    if COMMAND[0] == "dd":
        DUMP_ADDRESS += 4
        DUMP = get_dump(DUMP_ADDRESS)
        LAST_COMMAND = "(dd)"
        REFRESH = False
    #change dump address up        
    if COMMAND[0] == "du":
        if DUMP_ADDRESS >= 4:
            DUMP_ADDRESS -= 4
        DUMP = get_dump(DUMP_ADDRESS)
        LAST_COMMAND = "(du)"
        REFRESH = False
        
    
    #change stack address
    if COMMAND[0] == "stack":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                SP_offset = addr
                STACK = get_stack(SP_offset)
        else:
            MESSAGE = "stack usage: stack [OFFSET]"
        LAST_COMMAND = "(stack)"
        REFRESH = False
        
    #change stack address down
    if COMMAND[0] == "sd":
        SP_offset += 4
        STACK = get_stack(SP_offset)
        LAST_COMMAND = "(sd)"
        REFRESH = False
    #change stack address up        
    if COMMAND[0] == "su":
        if SP_offset >= 4:
            SP_offset -= 4
        STACK = get_stack(SP_offset)
        LAST_COMMAND = "(su)"
        REFRESH = False
        
    
    #change instr address
    if COMMAND[0] == "instr":
        if len(COMMAND) > 1:
            addr = parse_number(COMMAND[1])
            if addr >= 0:
                PC_offset = addr
                P_INS = get_code(PC_offset)
        else:
            MESSAGE = "instr usage: instr [OFFSET]"
        LAST_COMMAND = "(instr)"
        REFRESH = False
        
    #change stack address down
    if COMMAND[0] == "id":
        PC_offset += 4
        P_INS = get_code(PC_offset)
        LAST_COMMAND = "(id)"
        REFRESH = False
    #change stack address up        
    if COMMAND[0] == "iu":
        if PC_offset >= 4:
            PC_offset -= 4
        P_INS = get_code(PC_offset)
        LAST_COMMAND = "(iu)"
        REFRESH = False
        
    #update registers        
    if COMMAND[0] == "reg":
        FLAGS, REGISTERS = get_registers()
        LAST_COMMAND = "(reg)"
        REFRESH = False        
        

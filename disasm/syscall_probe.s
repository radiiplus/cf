/*  syscall_probe.s -- hand-written x86-64 asm: the *opcode* layer of the
 *  JSON -> syscall investigation.
 *
 *  Goal: make the instruction-level crossing visible without libc wrappers.
 *  This program performs, with raw opcodes only:
 *      socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0)   -> rax = 41
 *      connect(fd, &sa, 16)                            -> rax = 42
 *      write(dirfd, "record\n", 7)                      -> rax = 1
 *      close(fd)                                       -> rax = 3
 *      exit_group(0)                                   -> rax = 231
 *
 *  The sockaddr_in is built from immediates that a C compiler would have got
 *  from an allow-listed slot table -- i.e. operands are program constants,
 *  never request data. That is exactly the property we want to be able to
 *  point at in machine code when asking: "could JSON ever reach here?"
 *
 *  Build: gcc -nostdlib -no-pie -static -o syscall_probe syscall_probe.s
 */

        .equ SYS_WRITE,   1
        .equ SYS_CLOSE,   3
        .equ SYS_SOCKET,  41
        .equ SYS_CONNECT, 42
        .equ SYS_EXITGRP, 231
        .equ AF_INET,     2
        .equ SOCK_STREAM, 1
        .equ PORT_AUDIT,  0x4a9c          /* 19100 decimal, network order below */

        .section .rodata
msg:    .ascii "asm-record\n"
        .set msglen, . - msg

        .text
        .globl _start
_start:
        /* ---- struct sockaddr_in sa (on stack, all operands are immediates) */
        sub  $16, %rsp                  # room for sockaddr_in
        movw $AF_INET, (%rsp)           # sin_family = 2
        /* htons(19100): 19100 = 0x4A9C -> net order 0x9C4A */
        movw $0x9C4A, 2(%rsp)           # sin_port
        /* 127.0.0.1 = 0x7F000001, little-endian stored as-is for IPv4 loopback */
        movl $0x0100007F, 4(%rsp)       # sin_addr
        movq $0, 8(%rsp)                # pad

        /* ---- socket(2) : direct opcode, no libc ---- */
        movl $SYS_SOCKET, %eax
        movl $AF_INET, %edi
        movl $SOCK_STREAM, %esi         # | SOCK_CLOEXEC omitted for clarity
        xorl %edx, %edx
        syscall                         # <-- THE KERNEL CROSSING (fd in rax)
        movl %eax, %r8d                 # keep fd

        /* ---- connect(2) : operand came from stack constants above ---- */
        movl %r8d, %edi
        movl $SYS_CONNECT, %eax
        movq %rsp, %rsi                 # &sa
        movl $16, %edx
        syscall                         # <-- second crossing; rax = 0 or -errno

        /* ---- record the outcome by fd number, not by parsing anything ---- */
        movl %r8d, %edi                 # fd (stdout==1 if connect used dup? no:
                                        # we simply write to fd 1)
        movl $1, %edi
        movl $SYS_WRITE, %eax
        leaq msg(%rip), %rsi
        movl $msglen, %edx
        syscall

        /* ---- close the socket fd ---- */
        movl %r8d, %edi
        movl $SYS_CLOSE, %eax
        syscall

        /* ---- exit_group(0) ---- */
        xorl %edi, %edi
        movl $SYS_EXITGRP, %eax
        syscall

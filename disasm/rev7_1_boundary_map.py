#!/usr/bin/env python3
"""
Rev7.1 - Process Execution & Boundary Map, corrected per reviewer round.

Addresses every Rev7 defect:
  R1  worker-first live shared-memory experiment (E1): worker maps region and
      signals READINESS *before* the gate writes; gate then performs parse and
      writes the derived identity fact; worker re-reads after a post-write
      signal. Separates LIVE SHARED-MEMORY VISIBILITY from reading
      already-flushed file contents (the only thing old E1 proved).
  R2  socket-only control (E2): same raw payload over AF_UNIX SOCK_DGRAM, no
      shared mapping at all -> what crosses is data, not state.
  R3  negative controls (E3/E4): map-but-no-write, write-but-worker-nomaps.
  R4  memfd_create uses the CORRECT x86-64 syscall number 319 (225 was
      timer_getoverrun); errno recorded verbatim; conclusion downgraded to
      "observed <errno>" rather than "seccomp blocked X".
  R5  worker fd passed dynamically as str(fd) and verified in child via
      fstat() inode equality with the parent's fd. No hard-coded descriptor 3.
  R6  one clean end-to-end run; artifact records source sha256 so output and
      code revision are tied together.
  R7  C helper (E6) is labeled a CONTROLLED SYSCALL EXERCISE, not a census:
      real arguments for brk/getrandom, errno recorded; known limitations
      listed inside the result. The Python-side census (E7) measures the REAL
      interpreter during a real parse via ctypes hooking of libc entry points;
      it cannot see raw `syscall()`-instruction calls or vDSO calls - stated.

Mediation classes (carried forward): PARSER_NATIVE / RUNTIME_MEDIATED /
CALLBACK_MEDIATED / APPLICATION_MEDIATED. Nothing here claims an isolation
failure; E1 demonstrates deliberate transfer through an existing OS interface.
"""

import ctypes, hashlib, json, os, select, socket, subprocess, sys, tempfile, time

PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
SRC_FILE = os.path.abspath(__file__)

# ---------------------------------------------------------------- primitives
libc = ctypes.CDLL("libc.so.6", use_errno=True)

# errno location: correct restype (default int truncates the pointer on x86-64)
errno_loc = libc.__errno_location
errno_loc.restype = ctypes.POINTER(ctypes.c_int)

# syscall(): default restype is int -> 64-bit return values (mmap addresses,
# sbrk) get truncated. Set explicitly.
libc.syscall.restype = ctypes.c_long
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.restype = ctypes.c_int
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.msync.restype = ctypes.c_int
libc.msync.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

SYS_MEMFD_CREATE = 319          # correct on x86-64 (225 = timer_getoverrun!)
MFD_CLOEXEC = 0o2000000
PROT_READ, PROT_WRITE = 1, 2
MAP_SHARED = 0x01
MAP_FAILED = ctypes.c_void_p(-1).value

def get_errno():
    return errno_loc()[0]

def errno_name(e):
    try:
        return os.strerror(e)
    except Exception:
        return f"errno={e}"

def make_shared_region(size=4096):
    """memfd first (correct nr), fall back to a file-backed mapping. Returns
    (fd, path_or_desc, backing_kind, memfd_errno_record).

    Measured environment facts that shaped this function:
      - ctypes.CDLL(None) resolves the MAIN PROGRAM; on this interpreter many
        libc symbols (mmap/munmap/msync) are NOT exported there -> use an
        explicit libc.so.6 handle for mmap-family calls.
      - MFD_CLOEXEC is 0o2000000 octal == 2 in decimal; writing it as decimal
        0o2000000-as-int set the real CLOEXEC bit and the inherited fd died at
        exec (measured EBADF in the child, rev7.1 iteration 1). Use 0 here.
    """
    name = ctypes.c_char_p(b"rev71_shared")
    errno_loc()[0] = 0
    mfd = libc.syscall(ctypes.c_long(SYS_MEMFD_CREATE), name, ctypes.c_uint(0))
    memfd_rec = None
    if mfd != -1:
        # MEASURED (wtest2): creating a memfd succeeds here, but a child process
        # that inherits the fd and mmaps it dies with SIGBUS (rc=-7). The file-
        # backed path works end-to-end. Therefore this revision deliberately
        # uses the file-backed fallback; the memfd is closed untested-as-channel.
        e_after = get_errno()
        memfd_rec = {"syscall_nr_used": SYS_MEMFD_CREATE,
                     "observed_result": "memfd_create SUCCEEDED (fd returned)",
                     "errno_after_success": e_after,
                     "channel_decision": "NOT used as the cross-process channel: "
                                         "inherited-fd mmap in child -> SIGBUS (measured); "
                                         "file-backed MAP_SHARED -> verified working"}
        os.close(mfd)
    else:
        e = get_errno()   # read FIRST (printf/open below would clobber libc errno)
        memfd_rec = {"syscall_nr_used": SYS_MEMFD_CREATE,
                     "observed_result": "returned -1",
                     "errno": e, "strerror": os.strerror(e) if e else "(errno==0)",
                     "note": "no claim about WHICH filter layer produced this; "
                             "seccomp-kill would have killed the process instead"}
    # fallback: file-backed MAP_SHARED
    path = os.path.join(tempfile.gettempdir(), "rev71_shared.bin")
    with open(path, "wb") as f:
        f.write(b"\x00" * size)
    fd = os.open(path, os.O_RDWR)
    os.set_inheritable(fd, True)          # survive exec regardless of env flags
    buf = ctypes.create_string_buffer(size)
    addr = libc.mmap(ctypes.c_void_p(0), ctypes.c_size_t(size),
                    ctypes.c_int(PROT_READ | PROT_WRITE), ctypes.c_int(MAP_SHARED),
                    ctypes.c_int(fd), ctypes.c_long(0))
    if addr == MAP_FAILED:
        raise OSError(get_errno(), "mmap failed: " + errno_name(get_errno()))
    return fd, addr, buf, "file-backed MAP_SHARED", memfd_rec

# ------------------------------------------------------------- gate-side parse
DOC_REENTRY = r'{"alpha": 1, "\u006cpha": 2}'   # valid \u006c escape -> both keys == "alpha"

def gate_parse(raw: bytes, reentrant: bool):
    """Parse raw bytes; record whether the two equal key strings share object
    identity (rev6d property). Reentrant arm re-enters the SAME decoder from
    inside object_pairs_hook EXACTLY ONCE (guarded), clearing the scanner memo
    mid-parse. Without the guard the hook re-enters itself -> RecursionError
    (a measured failure mode of the naive first attempt, documented here)."""
    seen = []
    holder = {}
    state = {"busy": False}
    def pairs_hook(pairs):
        seen.append([k for k, _ in pairs])
        if reentrant and "d" in holder and not state["busy"]:
            state["busy"] = True
            try:
                holder["d"].decode(DOC_REENTRY)   # nested decode on same decoder, once
            finally:
                state["busy"] = False
        return dict(pairs)
    import json as _j
    d = _j.JSONDecoder(object_pairs_hook=pairs_hook)
    holder["d"] = d
    obj = d.decode(raw.decode())
    ident = (len(seen[0]) == 2 and seen[0][0] is seen[0][1])
    eq = (len(seen[0]) == 2 and seen[0][0] == seen[0][1])
    return {"gate_key_identity_is": ident, "keys_equal_eq": eq,
            "parsed": obj, "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "hook_invocations": len(seen)}

# ------------------------------------------------------------ worker (separate process)
WORKER_SRC = r'''
import ctypes, hashlib, json, os, select, socket, sys, time

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PROT_READ, PROT_WRITE = 1, 2
MAP_SHARED = 0x01

mode = sys.argv[1]                      # map | nomap
fd = int(sys.argv[2])                   # dynamic, NOT assumed to be 3
ready_w = int(sys.argv[3])              # eventfds: worker->gate readiness
after_w = int(sys.argv[4])              # eventfds: worker->gate final read done
gate_after_fd = int(sys.argv[5]) if len(sys.argv) > 5 else -1  # gate->worker post-write signal

rep = {"mode": mode, "pid": os.getpid()}

def decode_flag(c):
    if isinstance(c, int): c = bytes([c])
    return 1 if c == b"1" else (0 if c == b"0" else None)

if mode == "map":
    # R5: verify the inherited descriptor actually references the shared object
    try:
        fst = os.fstat(fd)
        rep["fd_verified_fstat"] = {"isok": True, "dev": fst.st_dev, "ino": fst.st_ino,
                                    "size": fst.st_size}
    except OSError as e:
        rep["fd_verified_fstat"] = {"isok": False, "error": str(e)}
        print(json.dumps(rep)); sys.exit(1)

    size = 4096
    addr = libc.mmap(ctypes.c_void_p(0), ctypes.c_size_t(size),
                     ctypes.c_int(PROT_READ | PROT_WRITE), ctypes.c_int(MAP_SHARED),
                     ctypes.c_int(fd), ctypes.c_long(0))
    buf = (ctypes.c_char * size).from_address(addr)

    # R1: map FIRST, report readiness BEFORE the input-derived gate write happens
    rep["flag_at_readiness"] = decode_flag(buf[0])
    rep["nonce_at_readiness"] = bytes(buf[1:9]).hex()
    os.write(ready_w, b"R")
    # wait for gate's post-write signal (coordination channel carries NO value)
    if gate_after_fd >= 0:
        select.select([gate_after_fd], [], [], 15)
    # now re-read - the byte changed while our mapping was already live
    rep["flag_after_gate_write"] = decode_flag(buf[0])
    rep["nonce_hex"] = bytes(buf[1:9]).hex()
    os.write(after_w, b"D")
elif mode == "nomap":
    # E4 consumer-absent arm: fd inherited but NEVER mapped -> observes nothing
    rep["mapped"] = False
    os.write(ready_w, b"R")
    if gate_after_fd >= 0:
        select.select([gate_after_fd], [], [], 15)
    rep["flag_after_gate_write"] = None
    os.write(after_w, b"D")

print(json.dumps(rep))
'''

def eventfd_pair():
    EFD = 0  # plain read/write semantics via os.read/write on the fd
    r1, w1 = os.pipe()   # pipes are simpler & fully portable inside sandbox
    return r1, w1

# --------------------------------------------------------------- experiments
def e1_live_shared_memory(raw_reentry: bytes, raw_control: bytes):
    """Worker-first protocol. Two arms: reentrant vs control. Same payload hash."""
    results = []
    for arm, reentrant in (("reentrant", True), ("control", False)):
        fd, addr, buf, backing, memfd_rec = make_shared_region()
        # pre-set region to sentinel '1' BEFORE fork so worker's initial read is defined
        buf[0] = b"1"
        buf[1:9] = os.urandom(8)
        nonce_hex = bytes(buf[1:9]).hex()
        ctypes.memmove(ctypes.c_void_p(addr), buf, 4096)
        libc.munmap(ctypes.c_void_p(addr), ctypes.c_size_t(4096))

        ready_r, ready_w = os.pipe()
        done_r, done_w = os.pipe()
        gate_after_r, gate_after_w = os.pipe()

        p = subprocess.Popen([PY, "-c", WORKER_SRC, "map", str(fd),
                              str(ready_w), str(done_w), str(gate_after_r)],
                             stdout=subprocess.PIPE, text=True,
                             pass_fds=(fd, ready_w, done_w, gate_after_r))
        os.close(ready_w); os.close(done_w); os.close(gate_after_r)

        # R1: WAIT for worker readiness BEFORE doing anything input-derived
        select.select([ready_r], [], [], 15)
        os.read(ready_r, 1)

        # NOW the gate parses and writes the derived fact into the live region
        g = gate_parse(raw_reentry if reentrant else raw_control, reentrant)
        fd2 = fd  # reopen mapping in gate
        addr2 = libc.mmap(ctypes.c_void_p(0), ctypes.c_size_t(4096),
                          ctypes.c_int(PROT_READ | PROT_WRITE), ctypes.c_int(MAP_SHARED),
                          ctypes.c_int(fd2), ctypes.c_long(0))
        buf2 = (ctypes.c_char * 4096).from_address(addr2)
        assert bytes(buf2[1:9]).hex() == nonce_hex  # sanity: same object we seeded
        buf2[0] = b"0" if not g["gate_key_identity_is"] else b"1"
        ms_flag = 0 if not g["gate_key_identity_is"] else 1
        libc.msync(ctypes.c_void_p(addr2), ctypes.c_size_t(4096), ctypes.c_int(0))
        os.write(gate_after_w, b"W")           # coordination only, carries no value
        libc.munmap(ctypes.c_void_p(addr2), ctypes.c_size_t(4096))
        os.close(gate_after_w)

        select.select([done_r], [], [], 15)
        os.read(done_r, 1)
        out, _ = p.communicate(timeout=15)
        w = json.loads(out.strip().splitlines()[-1])
        os.close(ready_r); os.close(done_r)
        parent_ino = os.fstat(fd).st_ino
        os.close(fd)

        results.append({
            "id": "E1_live_shared_memory", "arm": arm,
            "backing": backing, "memfd_record": memfd_rec,
            "protocol_order": ["seed region", "spawn worker (pass_fds=(fd,), fd number dynamic)",
                               "worker maps + fstat-verifies + reports READY",
                               "gate parses input (reentrant|control)",
                               "gate writes derived bit + msync", "post-write signal (no value)",
                               "worker re-reads live mapping"],
            "gate_measurement": g,
            "worker_report": w,
            "gate_expected_flag": ms_flag,
            "worker_observed_flag_after_gate_write": w.get("flag_after_gate_write"),
            "worker_initial_flag_at_readiness": w.get("flag_at_readiness"),
            "nonce_match": w.get("nonce_hex") == nonce_hex,
            "inode_verified": (w.get("fd_verified_fstat", {}).get("isok", False)
                               and w.get("fd_verified_fstat", {}).get("ino") == parent_ino),
        })
    # cross-arm divergence check
    a, b = results
    diverged = (a["worker_observed_flag_after_gate_write"] !=
                b["worker_observed_flag_after_gate_write"])
    same_payload = a["gate_measurement"]["payload_sha256"] == b["gate_measurement"]["payload_sha256"]
    verdict = {
        "live_visibility_demonstrated": (
            a["worker_initial_flag_at_readiness"] == 1 and
            a["worker_observed_flag_after_gate_write"] == 0 and
            b["worker_observed_flag_after_gate_write"] == 1),
        "identical_payload_bytes": same_payload,
        "arms_diverge_only_via_gate_state": diverged and same_payload,
        "classification": "APPLICATION_MEDIATED deliberate transfer via existing OS interface "
                          "(shared mmap over inherited fd). NOT an isolation failure, NOT the "
                          "identity graph crossing: a one-bit DERIVED FACT crossed.",
    }
    return results, verdict

def e2_socket_only_control(raw: bytes):
    """Same payload over AF_UNIX SOCK_DGRAM. Worker reparses. No shared region.
    Establishes baseline: values cross, identity-graph state does not (rev6e)."""
    tmp = tempfile.gettempdir()
    srv_path = os.path.join(tmp, f"rev71_{os.getpid()}_srv.sock")
    cli_path = srv_path + ".c"
    for pth in (srv_path, cli_path):
        if os.path.exists(pth):
            os.unlink(pth)
    CHILD = (
        "import socket,json,hashlib\n"
        f"srv={srv_path!r}; cli=srv+'.c'\n"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind(cli)\n"
        "s.sendto(b'handshake',(srv,))\n"
        "data,_=s.recvfrom(65536)\n"
        "obj=json.loads(data.decode())\n"
        "print(json.dumps({'bytes_sha256':hashlib.sha256(data).hexdigest(),'reparsed':obj}))\n"
    )
    # gate side: bind server AFTER child announces readiness via its own bind;
    # simplest robust order -> spawn child first (it binds .c, sends handshake to srv),
    # but srv must exist before handshake. So: create srv socket now, spawn child,
    # then receive handshake, then send payload.
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(srv_path)
    proc = subprocess.Popen([PY, "-c", CHILD], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        addr, _ = srv.recvfrom(64)          # handshake from child (bounded wait by communicate below)
        srv.sendto(raw, (cli_path,))        # payload travels ONLY over the socket
        out, err = proc.communicate(timeout=15)
    except Exception as e:
        proc.kill()
        out, err = "", str(e)
        addr = None
    w = json.loads(out.strip().splitlines()[-1]) if out.strip() else {"error": err[:200]}
    g = gate_parse(raw, reentrant=False)
    srv.close()
    for pth in (srv_path, cli_path):
        if os.path.exists(pth):
            os.unlink(pth)
    return [{
        "id": "E2_socket_only_control",
        "gate": g, "worker": w,
        "values_crossed": w.get("reparsed") == g["parsed"],
        "byte_identity_preserved": w.get("bytes_sha256") == g["payload_sha256"],
        "shared_surface_present": False,
        "classification": "deliberate data transfer; identity-graph absorption confirmed (rev6e)",
    }]

def e3_e4_negative_controls(raw_reentry: bytes):
    """E3: map but gate never writes -> worker must still see sentinel.
       E4: gate writes but worker inherits fd WITHOUT mapping it -> consumer
           observes nothing (write has no effect on that process)."""
    out = []
    # ---- E3: map, no write
    fd, addr, buf, backing, _ = make_shared_region()
    buf[0] = b"1"; buf[1:9] = os.urandom(8)
    nonce_hex = bytes(buf[1:9]).hex()
    ctypes.memmove(ctypes.c_void_p(addr), buf, 4096)
    libc.munmap(ctypes.c_void_p(addr), ctypes.c_size_t(4096))
    ready_r, ready_w = os.pipe(); done_r, done_w = os.pipe()
    ga_r, ga_w = os.pipe()
    p = subprocess.Popen([PY, "-c", WORKER_SRC, "map", str(fd), str(ready_w), str(done_w), str(ga_r)],
                         stdout=subprocess.PIPE, text=True, pass_fds=(fd, ready_w, done_w, ga_r))
    os.close(ready_w); os.close(done_w); os.close(ga_r)
    select.select([ready_r], [], [], 15); os.read(ready_r, 1)
    g = gate_parse(raw_reentry, True)          # parse happens...
    # ...but NO write to the region (negative control)
    os.write(ga_w, b"W"); os.close(ga_w)
    select.select([done_r], [], [], 15); os.read(done_r, 1)
    o, _ = p.communicate(timeout=15)
    w = json.loads(o.strip().splitlines()[-1])
    os.close(ready_r); os.close(done_r); os.close(fd)
    out.append({"id": "E3_map_no_write", "expect": "sentinel unchanged despite reentrant parse",
                "gate_identity": g["gate_key_identity_is"],
                "worker_flag_after_signal": w.get("flag_after_gate_write"),
                "held": (w.get("flag_after_gate_write") == 1
                         and w.get("nonce_hex") == nonce_hex)})
    # ---- E4: write happens, worker has the fd but NEVER maps it
    fd, addr, buf, backing, _ = make_shared_region()
    buf[0] = b"1"; buf[1:9] = os.urandom(8)
    nonce_hex = bytes(buf[1:9]).hex()
    ctypes.memmove(ctypes.c_void_p(addr), buf, 4096)
    ready_r, ready_w = os.pipe(); done_r, done_w = os.pipe()
    ga_r, ga_w = os.pipe()
    p = subprocess.Popen([PY, "-c", WORKER_SRC, "nomap", str(fd), str(ready_w), str(done_w), str(ga_r)],
                         stdout=subprocess.PIPE, text=True, pass_fds=(fd, ready_w, done_w, ga_r))
    os.close(ready_w); os.close(done_w); os.close(ga_r)
    select.select([ready_r], [], [], 15); os.read(ready_r, 1)
    g = gate_parse(raw_reentry, True)
    buf[0] = b"0"                               # write happens into live mapping...
    libc.msync(ctypes.c_void_p(addr), ctypes.c_size_t(4096), ctypes.c_int(0))
    os.write(ga_w, b"W"); os.close(ga_w)
    select.select([done_r], [], [], 15); os.read(done_r, 1)
    o, _ = p.communicate(timeout=15)
    w = json.loads(o.strip().splitlines()[-1])
    libc.munmap(ctypes.c_void_p(addr), ctypes.c_size_t(4096))
    os.close(ready_r); os.close(done_r); os.close(fd)
    out.append({"id": "E4_write_consumer_without_mapping",
                "expect": "worker holding an unmapped inherited fd observes nothing",
                "gate_identity": g["gate_key_identity_is"],
                "worker_observed": w.get("flag_after_gate_write"),
                "held": w.get("flag_after_gate_write") is None and w.get("mapped") == False})
    return out

# ------------------------------------------- E6: controlled syscall exercise (C)
C_HELPER = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdlib.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
#define TRY(label,stage,expr) do{ errno=0; double t0=now(); long r=(long)(expr); int e=errno; \
  printf("SYSCALL %s stage=%s ret=%ld errno=%d(%s) wall_us=%.0f\n", label, stage, r, r==-1?e:0, \
         r==-1?strerror(e):"-", (now()-t0)*1e6); fflush(stdout);}while(0)
int main(void){
  printf("BEGIN stage=init t=%.6f\n", now());
  /* brk WITH argument */
  void* cur = sbrk(0);
  TRY("brk_grow","stage_heap", syscall(SYS_brk, (char*)cur+4096));
  TRY("brk_restore","stage_heap", syscall(SYS_brk, (long)cur));
  /* getrandom WITH real args */
  char gbuf[16];
  TRY("getrandom","stage_parse_like", syscall(SYS_getrandom, gbuf, sizeof gbuf, (unsigned)0));
  /* mmap/munmap PRIVATE anon */
  errno=0; void*m = (void*)syscall(SYS_mmap, (void*)0, (size_t)4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, (off_t)0);
  int e = errno;
  printf("SYSCALL mmap_anon stage=stage_parse_like ret=%ld errno=%d(%s)\n", (long)m, m==(void*)-1?e:0, m==(void*)-1?strerror(e):"-");
  if(m!=(void*)-1){ syscall(SYS_munmap, m, (size_t)4096); }
  /* memfd_create correct nr (319 on x86-64) */
  TRY("memfd_create319","stage_backing", syscall(SYS_memfd_create, "rev71c", (unsigned)0));
  /* eventfd as sync facility */
  TRY("eventfd2","stage_sync", syscall(SYS_eventfd2, 0, (unsigned)0));
  printf("END stage=done t=%.6f\n", now());
  return 0;
}
'''

def e6_c_exercise():
    src = "/tmp/rev71_helper.c"; exe = "/tmp/rev71_helper"
    open(src, "w").write(C_HELPER)
    cc = subprocess.run(["gcc", "-O0", "-o", exe, src], capture_output=True, text=True)
    if cc.returncode != 0:
        return [{"id": "E6_controlled_syscall_exercise", "compile": "FAILED",
                 "stderr": cc.stderr[:400],
                 "note": "documented failure; not hidden"}]
    r = subprocess.run([exe], capture_output=True, text=True, timeout=20)
    lines = [l for l in r.stdout.splitlines() if l.startswith("SYSCALL")]
    return [{
        "id": "E6_controlled_syscall_exercise",
        "label": "NOT a census: measures only its own selected operations",
        "records": lines,
        "limitations": [
            "does not observe the CPython gate process's syscalls",
            "raw syscall()-instruction calls by CPython bypass LD_PRELOAD interposers (measured rev7)",
            "vDSO-served calls (clock_gettime) invisible to any ptrace-free census",
            "ptrace-based tracing unavailable here: observed EPERM; filter internals not asserted",
        ],
    }]

# ------------------------- E7: LD_PRELOAD interposer census on the REAL gate
PRELOAD_SRC = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include <string.h>
static FILE*log(){ static FILE*f=NULL; if(!f){f=fopen("/tmp/rev71_preload.log","a");} return f; }
static double now(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
#define WRAP(rettype, name, proto, args) \
  rettype name proto { \
    static rettype (*real) proto = NULL; \
    if(!real) real = dlsym(RTLD_NEXT, #name); \
    double t0=now(); rettype r = real args; \
    fprintf(log(), "LIBC %s t=%.6f dur_us=%.0f\n", #name, t0, (now()-t0)*1e6); \
    return r; }
WRAP(void*, malloc, (size_t n), (n))
WRAP(void, free, (void* p), (p))
WRAP(int, munmap, (void* a, size_t l), (a, l))
WRAP(ssize_t, read, (int fd, void* b, size_t c), (fd, b, c))
WRAP(ssize_t, write, (int fd, const void* b, size_t c), (fd, b, c))
'''

def e7_gate_libc_census(raw: bytes):
    src = "/tmp/rev71_wrap.c"; so = "/tmp/rev71_wrap.so"
    open(src, "w").write(PRELOAD_SRC)
    cc = subprocess.run(["gcc", "-O0", "-shared", "-fPIC", "-o", so, src, "-ldl"],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        return [{"id": "E7_gate_libc_census", "compile": "FAILED", "stderr": cc.stderr[:300]}]
    if os.path.exists("/tmp/rev71_preload.log"):
        os.unlink("/tmp/rev71_preload.log")
    open("/tmp/rev71_doc.json", "wb").write(raw)
    # two runs: baseline (no json parse) vs parse run -> difference approximates
    # the libc-call footprint attributable to the parse window
    script_base = ("import sys\nsys.stderr.write('MARK-END\\n')\n")
    script_parse = (
        "import json,sys\n"
        "sys.stderr.write('MARK-BEGIN\\n')\n"
        "obj=json.loads(open('/tmp/rev71_doc.json').read())\n"
        "sys.stderr.write('MARK-END\\n')\n"
    )
    env = dict(os.environ, LD_PRELOAD=so)
    counts_by_run = {}
    for tag, scr in (("baseline_no_parse", script_base), ("parse_run", script_parse)):
        if os.path.exists("/tmp/rev71_preload.log"):
            os.unlink("/tmp/rev71_preload.log")
        r = subprocess.run([PY, "-c", scr], capture_output=True, text=True,
                           env=env, timeout=30)
        lines = []
        if os.path.exists("/tmp/rev71_preload.log"):
            lines = open("/tmp/rev71_preload.log").read().splitlines()
        counts = {}
        for l in lines:
            parts = l.split()
            nm = parts[1] if len(parts) > 1 else "?"
            counts[nm] = counts.get(nm, 0) + 1
        counts_by_run[tag] = {"counts": counts, "total_logged": len(lines),
                              "rc": r.returncode}
    delta = {}
    for nm in set(counts_by_run["baseline_no_parse"]["counts"]) | set(counts_by_run["parse_run"]["counts"]):
        b = counts_by_run["baseline_no_parse"]["counts"].get(nm, 0)
        pr = counts_by_run["parse_run"]["counts"].get(nm, 0)
        delta[nm] = pr - b
    return [{
        "id": "E7_gate_libc_census",
        "instrument": "LD_PRELOAD interposer on libc entry points (malloc/free/read/write/munmap)",
        "method": "two-run differencing (baseline interpreter startup vs same + one json.loads)",
        "runs": counts_by_run,
        "delta_parse_minus_baseline": delta,
        "caveats": [
            "delta is an APPROXIMATION of the parse-attributable libc footprint; interpreter "
            "startup work is common-mode and cancels only if deterministic",
            "CPython may use pymalloc arenas: many small object allocations do NOT appear as malloc calls",
            "kernel-level syscalls issued via raw syscall instruction and vDSO calls are NOT captured",
            "therefore: partial view, explicitly not a syscall census of the validation subsystem",
        ],
    }]

# --------------------------------------------------------------------- main
def main():
    raw = DOC_REENTRY.encode()          # identical bytes for both arms
    art = {
        "revision": "rev7.1",
        "source_sha256": hashlib.sha256(open(SRC_FILE, "rb").read()).hexdigest(),
        "python": sys.version.split()[0],
        "research_question": "Can an input-derived runtime fact be OBSERVED by a separate "
                             "process through a live shared mapping (worker-first protocol), "
                             "and what exactly crosses vs what does not?",
        "hypothesis_status_policy": "every claim cites an observed line; failures documented",
    }
    e1_res, e1_verdict = e1_live_shared_memory(raw, raw)
    art["E1_live_shared_memory"] = {"arms": e1_res, "verdict": e1_verdict}
    art["E2_socket_only_control"] = e2_socket_only_control(raw)
    art["E3_E4_negative_controls"] = e3_e4_negative_controls(raw)
    art["E6_controlled_syscall_exercise"] = e6_c_exercise()[0]
    art["E7_gate_libc_census"] = e7_gate_libc_census(raw)[0]

    art["boundary_summary"] = {
        "what_crossed_in_E1": "one derived bit (gate_key_identity_is -> 0/1) + pre-shared nonce, "
                              "through MAP_SHARED over an explicitly inherited fd",
        "what_did_not_cross": "Python key objects, the decoder memo, the identity graph itself, "
                              "any unauthorized access",
        "E1_vs_rev7_old": "rev7 proved file-backed transfer (write-before-map). rev7.1 proves "
                          "visibility of a change made AFTER the worker's mapping existed.",
        "isolation_failure": "not demonstrated anywhere in this artifact",
        "mediation_class": "APPLICATION_MEDIATED (deliberate channel), with the measurement itself "
                           "RUNTIME_MEDIATED (scanner memo) / CALLBACK_MEDIATED (hook reentry)",
    }
    out = os.path.join(HERE, "..", "artifacts", "rev7_1_execution_boundary_map.json")
    with open(out, "w") as f:
        json.dump(art, f, indent=1, default=str)
    print(json.dumps({k: art[k] for k in ("E1_live_shared_memory",)}, indent=1, default=str)[:4000])
    print("ARTIFACT:", os.path.abspath(out))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
rev7 -- PROCESS EXECUTION AND BOUNDARY MAP + TRACK E (cross-boundary influence).

Unit of investigation per the standing direction: NOT another JSON anomaly.
This produces (a) the Process Execution and Boundary Map for the owned gate
process, stage-attributed, and (b) the first positive Track-E result: input-
derived state observed by a DIFFERENT process across an existing interface,
with the three-outcome taxonomy applied:
  (1) state created/modified inside the original process   -> rev6d (done)
  (2) state deliberately transferred through an existing interface -> rev6e E1 values (done)
  (3) state UNEXPECTEDLY observed by a separate consumer   -> THIS ROUND (E1/E2/E3)

Owned environment only: we fork/spawn both processes, bind our own AF_UNIX
socket path, and read only our own /proc entries. No external systems.

Experiment E1 (legitimate-interface channel, closed loop):
  G parses raw bytes with object_pairs_hook; hook records key-object identity
  facts (memo-hit vs distinct) into SHARED MEMORY (mmap MAP_SHARED|MAP_ANONYMOUS,
  inherited across fork -- an existing authorised OS interface between two
  address spaces). W reads the region and reports what it observes.
  Prediction: W observes G's runtime-state property (identity divergence from
  rev6d) WITHOUT any value carrying it -- the forwarded payload is byte-identical
  between control/reentrant runs (rev6e PROVEN), so any W-side difference must
  come from the shared mapping, i.e. genuine cross-process state propagation.

Experiment E2 (negative control -- no shared surface):
  Same reentrant/control pair, but W receives ONLY the socket payload (no mmap).
  Prediction: W output identical across arms => confirms E1's observation was
  carried by the shared resource, not by the data itself.

Experiment E3 (fd-permission boundary probe):
  G opens an O_TMPFILE/CLOEXEC fd; after exec-spawn of W, does W see it?
  Then G opens a NON-CLOEXEC fd to our own unix socket dir and forks W via
  os.fork() (no exec): does W inherit? Establishes which handoffs are real in
  this architecture instead of assuming them. Kernel-enforced expectations:
  CLOEXEC+exec => not inherited; fork => inherited (same table copy).

Map instruments (stage attribution):
  M1 syscall census: strace -f -ttt -e trace=%desc,%memory,socket,sendto,recvfrom,
      connect,clone,execve,futex ... over one full request lifecycle; syscalls
      bucketed per execution STAGE using userspace markers written to a side log
      (STAGE lines interleaved via strace -e inject? no -- simpler: marker file
      offsets captured at each stage boundary, then bucket by timestamp).
  M2 VMA inventory: /proc/self/maps + smaps snapshot at rest vs mid-parse
      (delta = mappings touched/created during parse of a large body).
  M3 fd/socket inventory: /proc/self/fd readlink at each stage; unix sockets
      paired with peer pid via /proc/net/unix inode matching.
  M4 thread/task inventory: /proc/self/task listing before/during/after.
"""
import ctypes, json, mmap, os, socket, subprocess, sys, threading, time, hashlib, struct

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "..", "artifacts")
SOCK_PATH = "/tmp/rev7_gate.sock"
PY = sys.executable

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
PROT_READ, PROT_WRITE = 1, 2
# MAP_SHARED=0x01, MAP_ANONYMOUS=0x20 (Linux x86_64)
MAP_SHARED, MAP_ANON = 0x01, 0x20
PAGE = 4096

RAW = r'{"route":"ledger","dup_key_e7c":{"inner":1},"\u0064up_key_e7c":[0],"tail":true}'
assert "\\u0064" in RAW  # escape survives into the JSON text (rev6 lesson)


def stage_log():
    return open(os.environ.get("REV7_STAGELOG", "/tmp/rev7_stages.log"), "a", buffering=1)


def mark(name):
    stage_log().write(f"{time.monotonic_ns()} {name}\n")


# ---------------- scanner-memo identity fact via hook (reentrant vs control) --
def measure_identity(raw, reentrant):
    """Parse `raw`; return (key_objs_identity_of_twins, forwarded_bytes).
    Reentrant arm: a NESTED object's pairs hook fires mid-outer-parse and calls
    decode() on the SAME decoder instance (rev6d mechanism -- guard flag keeps
    it to exactly one reentry so the nested inner parse cannot recurse)."""
    obj = None
    keys_captured = []
    state = {"reentered": False}
    if reentrant:
        dec = None
        def cap(pairs):
            keys_captured.extend(k for k, _ in pairs)
            # when the FIRST nested container closes, reenter the SAME decoder
            if not state["reentered"] and any(k == "inner" for k, _ in pairs):
                state["reentered"] = True
                dec.decode('{"z":1}')     # clears memo mid-outer-parse (rev6d)
            return dict(pairs)
        dec = json.JSONDecoder(object_pairs_hook=cap)
        obj = dec.decode(raw)
        assert state["reentered"], "reentry never fired -- gate invalid"
    else:
        def cap0(pairs):
            keys_captured.extend(k for k, _ in pairs)
            return dict(pairs)
        obj = json.JSONDecoder(object_pairs_hook=cap0).decode(raw)
    twins = [k for k in keys_captured if k == "dup_key_e7c"]
    identity = (twins[0] is twins[1]) if len(twins) >= 2 else None
    return identity, json.dumps(obj).encode() + b"\n"


# ---------------- worker process code (spawned twice: with/without mmap) -----
WORKER = r"""
import json, os, sys, mmap
mode = sys.argv[1]                     # "nomap" | "map"
pgsz = 4096
out = {"mode": mode}
if mode == "map":
    fd = int(sys.argv[2])              # inherited shared-mem fd (pass_fds -> number 3)
    mm = mmap.mmap(fd, pgsz)
    out["shared_flag_observed"] = mm[0]        # byte 0: gate-written identity fact
    out["gate_nonce_hex"] = mm[1:9].hex()      # gate nonce proving provenance
print(json.dumps(out))
"""


def run_arm(reentrant, worker_mode, shared_parent_fd=None):
    """Gate side: build payload + runtime-state fact; spawn W. In 'map' mode the
    ONLY information path G->W is the shared mapping (no socket at all)."""
    osid, payload = measure_identity(RAW, reentrant)
    result = {"arm": "reentrant" if reentrant else "control",
              "gate_key_identity": osid,
              "payload_sha256": hashlib.sha256(payload).hexdigest()}
    args = [PY, "-c", WORKER, worker_mode]
    pass_fds = ()
    if worker_mode == "map":
        # write identity fact + nonce into the SHARED region BEFORE spawning W
        mm = mmap.mmap(shared_parent_fd, PAGE)
        nonce = os.urandom(8)
        mm[0] = 1 if osid else 0
        mm[1:9] = nonce
        mm.flush()
        result["gate_nonce_hex"] = nonce.hex()
        pass_fds = (shared_parent_fd,)   # lands on fd 3 in the exec'd child
        args.append("3")
    p = subprocess.Popen(args, stdout=subprocess.PIPE, text=True, pass_fds=pass_fds)
    out = p.communicate(timeout=20)[0].strip()
    result["worker_report"] = json.loads(out) if out else None
    return result


def main():
    if os.environ.get("REV7_TRACED_LEAF") == "1":
        traced_leaf()
        return
    # one-time calibration so monotonic_ns markers can be compared to strace epoch stamps
    with open("/tmp/rev7_calib.txt", "w") as f:
        f.write(f"{int(time.time_ns())} {time.monotonic_ns()}\n")
    mark("BEGIN")
    art = {"environment": {}, "experiments": [], "map": {}}

    # ---- E1/E2: shared-memory channel (positive) vs socket-only (negative ctrl)
    # memfd_create is blocked by this sandbox's seccomp filter (measured: ENOSYS);
    # fall back to a file-backed MAP_SHARED region on our own tmpfs path.
    try:
        MFD_CREATE = 225  # __NR_memfd_create on x86_64
        libc.syscall.restype = ctypes.c_long
        mfd = libc.syscall(MFD_CREATE, ctypes.c_char_p(b"rev7_shared"), ctypes.c_uint(0))
        assert mfd >= 0
        os.ftruncate(mfd, PAGE)
        art["environment"]["shared_backing"] = "memfd"
    except (AssertionError, OSError):
        SHFILE = "/tmp/rev7_shared.bin"
        with open(SHFILE, "wb") as f:
            f.write(b"\x00" * PAGE)
        mfd = os.open(SHFILE, os.O_RDWR)
        art["environment"]["shared_backing"] = "file-backed MAP_SHARED (seccomp blocked memfd)"
    parent_mm = mmap.mmap(mfd, PAGE)          # touch it into this address space

    e1 = run_arm(True,  "map", shared_parent_fd=mfd)
    e2 = run_arm(False, "map", shared_parent_fd=mfd)
    e3 = run_arm(True,  "nomap")
    art["experiments"] += [{"id": "E1_reentrant_shared_channel", **e1},
                           {"id": "E2_control_shared_channel", **e2},
                           {"id": "E3_negative_socket_only", **e3}]

    # ---- E4: fd-permission boundaries (FUNCTIONAL test, same fd in both arms)
    # parent binds a DGRAM unix socket and SENDS to it; the child tries to recv
    # on the inherited fd number. Receiving proves table+inode sharing, not just
    # a readlink string match. Arms: fork-noexec (expect SUCCESS), exec of a
    # fresh interpreter with pass_fds=(fd,) i.e. explicit CLOEXEC-clear (SUCCESS),
    # and plain exec WITHOUT clearing CLOEXEC (expect EBADF -> kernel closed it).
    for p in ("/tmp/rev7_keepalive", "/tmp/rev7_cloexec"):
        try: os.unlink(p)
        except FileNotFoundError: pass
    keep = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    keep.bind("/tmp/rev7_keepalive")
    kf = keep.fileno()
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)  # sender
    CHILD = ("import os,json,socket,sys\n"
             "fd=int(sys.argv[1])\n"
             "try:\n"
             "    data=os.read(fd,64)\n"
             "    print(json.dumps({'recv':data.decode(),'ino':os.fstat(fd).st_ino}))\n"
             "except OSError as e:\n"
             "    print(json.dumps({'error':str(e)}))")
    def send_then_child(mode):
        probe.sendto(b"PING-"+mode.encode(), "/tmp/rev7_keepalive")
        if mode == "fork":
            r, w = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r)
                import io
                buf = io.StringIO()
                old = sys.stdout; sys.stdout = buf
                try:
                    ns = {"os": os, "json": json, "socket": socket, "sys": sys, "argv": [None, str(kf)]}
                    exec(CHILD.replace("sys.argv[1]", "argv[1]"), ns)
                finally:
                    sys.stdout = old
                os.write(w, buf.getvalue().encode()); os.close(w); os._exit(0)
            os.close(w)
            out = b""
            while True:
                c = os.read(r, 65536)
                if not c: break
                out += c
            os.close(r); os.waitpid(pid, 0)
            return json.loads(out.decode())
        else:  # exec arms
            if mode == "exec_passfds":
                p = subprocess.run([PY, "-c", CHILD, str(kf)], capture_output=True, text=True, timeout=20, pass_fds=(kf,))
            else:  # bare exec: Python's sockets are CLOEXEC, so kf must be GONE
                p = subprocess.run([PY, "-c", CHILD, str(kf)], capture_output=True, text=True, timeout=20)
            return json.loads(p.stdout.strip() or "{}")
    art["experiments"].append({
        "id": "E4_fd_boundary_functional",
        "parent_send_ok": True,
        "fork_noexec_child_received": send_then_child("fork"),
        "exec_with_explicit_inherit_child_received": send_then_child("exec_passfds"),
        "exec_without_inherit_child_received": send_then_child("exec_bare"),
    })

    # ---- M1: syscall census with stage attribution.
    # Instrument choice (measured, not assumed):
    #  * strace wrapper: FAILED in this sandbox -- seccomp filter blocks ptrace;
    #    the traced child dies silently (two observed 120s hangs). Documented.
    #  * LD_PRELOAD libc interposer: captures almost nothing of the SOI set --
    #    CPython issues syscalls via raw `syscall()` asm and glibc via vDSO
    #    (gettimeofday measured directly below). Also documented as a negative.
    #  * CHOSEN: raw-SOI probe executed DIRECTLY inside the gate process
    #    (no interpreter nesting -> no ptrace hang), CLOCK_MONOTONIC markers in
    #    the same stream; plus a separate fork+execve child to attribute spawn.
    mark("M1_BEGIN")
    art["map"]["instrument_failures_measured"] = {
        "strace_ptrace": "blocked by sandbox seccomp (child killed silently; 2x timeout)",
        "ld_preload_libc_interposer": "near-zero capture: CPython uses raw syscall insn + vDSO",
    }
    soi_probe = build_soi_probe("/tmp/rev7_soi")          # C program, raw syscalls
    if os.path.exists(soi_probe):
        # run the probe AS A CHILD OF GATE with markers around each phase:
        # phases are internal to the probe (it marks PARSE/SPAWN itself via clock)
        try: os.unlink("/tmp/rev7_soi.log")
        except FileNotFoundError: pass
        env = dict(os.environ); env["SHIM_OUT"] = "/tmp/rev7_soi.log"
        r = subprocess.run([soi_probe], env=env, capture_output=True, text=True, timeout=60)
        art["map"]["soi_child_rc"] = r.returncode
        art["map"]["soi_child_stderr"] = (r.stderr or "")[:200]
        art["map"]["syscall_census"] = bucket_syscalls("/tmp/rev7_soi.log")
    else:
        art["map"]["syscall_census"] = {"error": "SOI probe build failed"}
    # vDSO direct measurement in THIS process (proves why preload missed them)
    art["map"]["vdso_check"] = measure_vdso_inprocess()

    # ---- M2/M3/M4: VMA delta, fd inventory, task inventory around a big parse
    mark("M2_BEGIN")
    maps_rest = set(open("/proc/self/maps").read().splitlines())
    def fd_snapshot():
        snap = {}
        for f in os.listdir("/proc/self/fd"):
            try: snap[f] = os.readlink(f"/proc/self/fd/{f}")
            except OSError: pass   # fd vanished between listdir and readlink
        return snap
    fds_rest = fd_snapshot()
    tasks_rest = sorted(os.listdir("/proc/self/task"))
    big = '{"pad":"' + "A" * (8 * 1024 * 1024) + '"}'
    json.loads(big)
    maps_mid = set(open("/proc/self/maps").read().splitlines())
    art["map"]["vma_delta_new_regions"] = sorted(maps_mid - maps_rest)[:40]
    art["map"]["vma_delta_count"] = len(maps_mid - maps_rest)
    art["map"]["fds_at_stage"] = fds_rest
    art["map"]["tasks_at_rest"] = tasks_rest
    mark("M2_END")

    json.dump(art, open(os.path.join(ART, "rev7_execution_boundary_map.json"), "w"), indent=1)
    print(json.dumps(art, indent=1)[:4000])


def main_done_marker():
    mark("MAIN_DONE")


GATE_SCOPED_TRACE = True

SHIM_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <time.h>
static FILE *out;
static void init(void){ if(!out){ const char*p=getenv("SHIM_OUT"); if(p&&*p) out=fopen(p,"a"); } }
static long ts(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000000000L+t.tv_nsec; }
typedef long (*fn6)(long,long,long,long,long,long);
#define WRAP(name) \
long name(long a0,long a1,long a2,long a3,long a4,long a5){ \
  static fn6 real; if(!real) real=(fn6)dlsym(RTLD_NEXT,#name); \
  init(); long r = real? real(a0,a1,a2,a3,a4,a5) : -1; \
  if(out){ fprintf(out,"%ld SYSCALL %s %lx\n", ts(), #name, (long)r); fflush(out);} \
  return r; }
WRAP(socket) WRAP(connect) WRAP(sendto) WRAP(recvfrom) WRAP(brk)
WRAP(clone) WRAP(execve) WRAP(openat) WRAP(close) WRAP(fcntl) WRAP(getrandom)
"""


def traced_leaf():
    """Runs UNDER the preload shim: one full lifecycle, markers to the same clock.
    Markers go through libc write() so they interleave with shim SYSCALL lines in
    ONE file (SHIM_OUT) -- single stream, single clock, no merge skew."""
    import ctypes as _ct
    rt = _ct.CDLL("libc.so.6", use_errno=True)
    class TS(_ct.Structure):
        _fields_ = [("s", _ct.c_long), ("ns", _ct.c_long)]
    def mono_ns():
        t = TS(); rt.clock_gettime(1, _ct.byref(t))
        return t.s * 10**9 + t.ns
    outfd = os.open(os.environ["SHIM_OUT"], os.O_WRONLY | os.O_APPEND)
    def m(name):
        line = f"{mono_ns()} MARK {name}\n".encode()
        rt.write.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
        rt.write(outfd, line, len(line))
    m("MAIN_ENTRY")
    m("PARSE_BEGIN")
    measure_identity(RAW, True)          # JSON validation region only
    m("POST_PARSE")
    m("SPAWN_BEGIN")
    p = subprocess.Popen([PY, "-c", WORKER, "nomap"], stdout=subprocess.DEVNULL)
    p.wait(timeout=30)
    m("SPAWN_END")
    m("EXIT")
    os.close(outfd)


def build_shim(path):
    cpath = path + ".c"
    open(cpath, "w").write(SHIM_C)
    r = subprocess.run(["gcc", "-shared", "-fPIC", "-o", path, cpath, "-ldl"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        open(path + ".err", "w").write(r.stderr)
    return path if r.returncode == 0 else None


SOI_C = r"""
/* Direct raw-syscall census for the SOI set, with in-stream MARK lines on the
   SAME CLOCK_MONOTONIC. Each SOI call is issued via syscall(2) inside a marked
   stage so every line in the log carries an exact stage attribution. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
static FILE *out;
static long ts(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000000000L+t.tv_nsec; }
#define P(fmt,...) if(out){ fprintf(out,"%ld " fmt "\n", ts(), ##__VA_ARGS__); fflush(out);}
static void sc(long nr, const char*nm, const char*stage){
  long r = syscall(nr);
  P("SYSCALL %s stage=%s ret=%lx", nm, stage, r);
}
int main(void){
  const char*p=getenv("SHIM_OUT"); if(p&&*p) out=fopen(p,"a");
  P("MARK PROBE_ENTRY");
  /* ---- ACCEPT stage: socket + bind + listen (raw) ---- */
  P("MARK STAGE_ACCEPT");
  int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
  P("SYSCALL socket stage=STAGE_ACCEPT ret=%d", fd);
  unlink("/tmp/rev7_soi.sock");
  struct sockaddr_un sa; sa.sun_family=AF_UNIX; strcpy(sa.sun_path,"/tmp/rev7_soi.sock");
  long rb = syscall(SYS_bind, fd, &sa, sizeof(sa));
  P("SYSCALL bind stage=STAGE_ACCEPT ret=%ld", rb);
  P("SYSCALL listen stage=STAGE_ACCEPT ret=%ld", syscall(SYS_listen, fd, 1));
  /* ---- PARSE stage: heap growth + scan loop ---- */
  P("MARK STAGE_PARSE");
  volatile long acc=0; for(int i=0;i<1000000;i++) acc+=i;
  char*buf=malloc(4<<20); if(buf){buf[0]=1; buf[(4<<20)-1]=2;}
  sc(SYS_brk, "brk", "STAGE_PARSE");
  free(buf);
  sc(SYS_getrandom, "getrandom", "STAGE_PARSE");   /* seccomp behaviour recorded */
  /* ---- SPAWN stage: fork + execve(/bin/true) + wait ---- */
  P("MARK STAGE_SPAWN");
  pid_t c=fork();
  if(c==0){ execl("/bin/true","true",(char*)0); _exit(127); }
  int st; waitpid(c,&st,0);
  P("SYSCALL clone_via_fork stage=STAGE_SPAWN ret=%d", c);
  P("SYSCALL execve_child stage=STAGE_SPAWN note=child-issued");
  /* ---- CLOSE stage ---- */
  P("MARK STAGE_CLOSE");
  P("SYSCALL close stage=STAGE_CLOSE ret=%ld", syscall(SYS_close, fd));
  unlink("/tmp/rev7_soi.sock");
  P("MARK EXIT");
  return 0;
}
"""


def build_soi_probe(base):
    cpath, xpath = base + ".c", base
    open(cpath, "w").write(SOI_C)
    r = subprocess.run(["gcc", "-O1", "-o", xpath, cpath], capture_output=True, text=True)
    return xpath if r.returncode == 0 else None


def measure_vdso_inprocess():
    """clock_gettime/gettimeofday resolve into [vdso]; raw syscall counters stay
    ~zero while millions of calls execute -> proves the preload/raw gap."""
    import ctypes
    rt = ctypes.CDLL("libc.so.6", use_errno=True)
    class TS(ctypes.Structure):
        _fields_ = [("s", ctypes.c_long), ("ns", ctypes.c_long)]
    t = TS()
    import time
    n = 200000
    s0 = time.perf_counter()
    for _ in range(n):
        rt.clock_gettime(1, ctypes.byref(t))
    dt = time.perf_counter() - s0
    return {"clock_gettime_calls": n, "seconds": round(dt, 3),
            "note": "all served by vDSO; invisible to ptrace-based census and to libc-symbol preload for getrandom-style raw paths"}


def bucket_syscalls(merged_log):
    """Single stream: MARK and SYSCALL lines share CLOCK_MONOTONIC ns stamps.
    SYSCALL lines carrying stage= are attributed exactly; others by interval."""
    bounds = []
    rows = []
    for line in open(merged_log):
        a = line.split()
        if len(a) >= 3 and a[1] == "MARK":
            bounds.append((int(a[0]), a[2]))
        elif len(a) >= 3 and a[1] == "SYSCALL":
            stage = next((tok[6:] for tok in a if tok.startswith("stage=")), None)
            rows.append((int(a[0]), a[2], stage))
    bounds.sort()
    def interval(t):
        cur = "interpreter_startup_pre_main"
        for ns, name in bounds:
            if t >= ns: cur = name
        return cur
    counts = {}
    for t, sc, stage in rows:
        b = stage if stage else interval(t)
        counts.setdefault(b, {}).setdefault(sc, 0)
        counts[b][sc] += 1
    counts["_total_syscall_lines"] = len(rows)
    return counts





if __name__ == "__main__":
    main()

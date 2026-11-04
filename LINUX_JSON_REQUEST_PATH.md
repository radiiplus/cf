# Linux path of a JSON HTTP request

This maps a typical inbound `POST /orders` with `Content-Type: application/json` on Linux. An **IP route** chooses where a packet goes; an **HTTP route** such as `/orders` is selected by a server or application after it has received and parsed HTTP. Linux does not identify JSON or choose application routes.

**Security result so far:** the concrete JSON-to-worker socket path documented below is expected operation in a synthetic local service. No vulnerability, authorization bypass, passwordless-authentication transition, or file-execution path has been established.

## Scope and local evidence

The example assumes a client reaches a local TCP listener, directly or through a reverse proxy. The exact path depends on the network device, namespace, firewall, server, TLS termination point, and HTTP version. Not every component below runs on every request.

Observed in this workspace on 2026-11-04:

| Observation | Meaning and limit |
| --- | --- |
| Amazon Linux 2023, x86-64, kernel `6.18.56-125.164.amzn2023.x86_64` | Identifies the running kernel; it does not identify an application stack. |
| `enp39s0` is up at `172.31.22.142/20` and uses the `ena` driver | This host exposes an AWS ENA network device. Its default IPv4 route goes via `172.31.16.1`. |
| `ss -ltnp` shows SSH on port 22, Java on loopback ports 18080/18081, and local development-tool listeners | No public HTTP/JSON listener was identified. The Java listener's protocol and routes were not verified. |
| `net.ipv4.ip_forward=0`; `firewalld` is inactive | This host is not configured as an IPv4 router through that sysctl. This does not establish that all packet filtering is absent. |
| `net.ipv4.tcp_syncookies=1`, `net.core.somaxconn=4096`, `net.ipv4.tcp_max_syn_backlog=512` | Kernel defaults/settings visible here, not proof of a particular application's effective backlog or traffic. |
| Kernel config includes netfilter, BPF, cgroups, seccomp, and optional kTLS | Availability does not imply any corresponding hook, rule, or offload is active. |

Cloud load balancers, AWS security groups, DNS, and a client's network are **outside** this Linux OS. They may decide whether a packet reaches this machine at all.

## Ubuntu source check

The path below also matches Ubuntu's official **Noble (24.04) kernel source tree**, checked at commit `28e5daf6ca5bdc7104d1d5877c7113e578c94e9e` on 2026-11-04. The relevant implementations include receive processing in [`net/core/dev.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/core/dev.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e), IPv4 local delivery in [`net/ipv4/ip_input.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/ipv4/ip_input.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e), TCP receive and connection lookup in [`net/ipv4/tcp_ipv4.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/ipv4/tcp_ipv4.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e), accept queues in [`net/ipv4/inet_connection_sock.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/ipv4/inet_connection_sock.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e), socket syscalls in [`net/socket.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/socket.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e), and TCP send/receive in [`net/ipv4/tcp.c`](https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/tree/net/ipv4/tcp.c?id=28e5daf6ca5bdc7104d1d5877c7113e578c94e9e). Canonical [documents the per-release source repositories](https://ubuntu.com/kernel/docs/how-to/source-code/obtain-kernel-source-git/). These source checks support the common Linux data path; they do not prove that optional hooks or offloads are enabled on any particular Ubuntu installation.

On Ubuntu, check [UFW, iptables, and nftables configuration](https://documentation.ubuntu.com/security/security-features/network/firewall/) rather than inferring firewall behavior from a service name. Ubuntu's [nftables documentation](https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/) describes ingress, prerouting, input, output, and postrouting hooks; actual chains depend on loaded rules. Ubuntu also [loads AppArmor by default](https://ubuntu.com/server/docs/security-apparmor/), so a confined server may encounter AppArmor checks at kernel security hooks. The ENA interface, IP addresses, listeners, sysctl values, and `firewalld` state in the table above describe **this Amazon Linux host**, not Ubuntu defaults. An Ubuntu installation needs its own runtime inspection to establish those details.

## End-to-end map

```text
Client (possibly via load balancer / reverse proxy)
  | Ethernet frames / IP packets / TCP segments
  v
NIC + driver -> RX interrupt/NAPI -> optional XDP -> packet buffer (skb)
  -> optional GRO -> optional tc ingress / netfilter / conntrack
  -> IP checks and local-delivery decision -> TCP checks, ordering, ACKs
  -> listening socket (new connection) or established socket receive queue
  -> readiness wakeup / epoll / io_uring / blocking read
  -> process reads bytes across syscall boundary
  -> optional TLS decryption -> HTTP parsing and body framing
  -> optional decompression -> JSON parsing -> validation
  -> middleware / authentication / HTTP route -> application handler
  -> optional database, files, cache, or other network calls
  -> JSON serialization -> HTTP response -> optional TLS encryption
  -> process writes bytes across syscall boundary
  -> TCP send queue, congestion/window control, segmentation
  -> optional netfilter/tc egress -> qdisc -> driver/NIC -> client
```

### 0. Before a request: listener setup

1. A server process starts under a service manager, container runtime, or shell. The kernel supplies process scheduling, virtual memory, file descriptors, credentials, namespaces, and cgroups. Its security policy (for example AppArmor on Ubuntu, or seccomp where configured) may restrict operations.
2. The server typically calls `socket()`, `setsockopt()`, `bind()`, and `listen()` for TCP. A socket belongs to a network namespace and has a local address, port, receive/send buffers, and a listen backlog. A front proxy may own the public listener while the application listens on another port or a Unix-domain socket.
3. The server registers descriptors with `epoll`, uses `io_uring`, or blocks in `accept()`/`read()`. Worker threads and runtimes can use different combinations. Once a TCP connection is accepted, many HTTP requests can reuse it; there is **not** necessarily one `accept()` per HTTP request.

### 1. Packet arrival and kernel ingress

1. The network device receives a frame and places data in memory, usually with DMA. Its driver signals receive work; Linux commonly processes batches with NAPI. On this host, the visible device driver is ENA; no packet-level trace was taken.
2. If configured, XDP runs very early and may pass, drop, or redirect a packet. The normal path allocates or associates an `sk_buff` (skb), Linux's packet metadata structure. GRO may combine compatible incoming segments for efficient processing. Driver offloads can change what work happens on the CPU.
3. Optional traffic-control ingress programs, netfilter hooks, connection tracking, NAT, and firewall policy can inspect, rewrite, or drop traffic. Their presence and order depend on configuration. A cloud security group acts before this host, outside these hooks.
4. IP validates the packet and decides whether its destination is local. If it is for another host and forwarding is enabled, it takes a forwarding path instead. For a local TCP listener, TCP validates the segment, tracks sequence numbers, handles retransmission/ACK behavior, and associates data with a socket.
5. A new TCP connection goes through the SYN handshake and then enters the listener's completed-connection queue. Backlog limits and SYN cookies can affect overload behavior. An established connection's payload goes into its socket receive queue. TCP is a **byte stream**: packet and `read()` boundaries do not equal HTTP request or JSON boundaries.

### 2. Kernel-to-process handoff

1. When a listening socket has a completed connection, or an established socket has readable data, the kernel wakes a waiting task or reports readiness via `epoll`/`io_uring`. The CPU scheduler chooses when that task runs.
2. The process obtains a connection with `accept4()` or receives bytes with `read()`, `recv()`, `recvmsg()`, or an asynchronous equivalent. These calls cross the user/kernel boundary and generally copy or otherwise transfer data into application-managed buffers. Reads may be partial and may contain portions of multiple requests.
3. File-descriptor limits, socket buffer limits, cgroup limits, scheduler contention, memory pressure, and security policy can delay or reject work. The kernel does not parse the HTTP path or JSON body at this boundary.

### 3. Bytes become an HTTP request and then JSON

1. If HTTPS terminates in this process, a TLS library normally decrypts bytes in user space. If a proxy terminates TLS, the backend receives its chosen downstream protocol. Linux kTLS is an optional acceleration path, not a default assumption.
2. The HTTP server parses the request line or HTTP/2 frames, headers, and message framing. It determines when the body is complete using the protocol's framing rules (for example `Content-Length`, chunked transfer encoding, or HTTP/2 DATA frames). It may enforce size/time limits and decode compressed content when configured.
3. The server/framework sees `Content-Type: application/json`, then a user-space JSON parser converts body bytes into values. The parser can reject malformed JSON. A schema or application validator checks types and business constraints. The content type is a claim in an HTTP header, not something the kernel verifies.
4. Middleware may handle logging, CORS, authentication, authorization, and rate limits. The HTTP router matches method and path (here `POST /orders`) and invokes a handler. Frameworks differ in whether middleware, body parsing, and route selection happen in exactly this order; some route before reading the body.
5. The handler may call a database, cache, filesystem, or another service. Those operations cause their own syscalls and may create separate socket traffic. They are application-specific, not automatic consequences of JSON.

### 4. Response and kernel egress

1. The handler produces a status, headers, and values. A serializer turns values into JSON bytes; the HTTP server frames the response. TLS encryption happens here if this process owns TLS.
2. `write()`, `send()`, `sendmsg()`, or an asynchronous equivalent passes bytes to the kernel's socket send path. A successful write usually means bytes were **queued**, not that the client received or processed them.
3. TCP applies flow and congestion control, segments data, tracks acknowledgements, and retransmits when needed. Optional output firewall/NAT, traffic control, and queueing disciplines run according to configuration. The driver and NIC transmit frames.
4. The connection may remain open for another request, close normally, or be reset. A client disconnect can arrive while the handler is still running; the application only notices if it observes cancellation, reads, or writes.

## Responsibilities by layer

| Component | Responsible for | Does not inherently do |
| --- | --- | --- |
| NIC/driver | Receive/transmit frames; DMA, interrupts/NAPI, possible offloads | HTTP routing or JSON parsing |
| IP and routing | Validate addresses; choose local delivery or forwarding | Match `/orders` |
| TCP/socket subsystem | Connections, ordered byte stream, buffering, flow/congestion control | Preserve request boundaries |
| Netfilter/tc/BPF, when configured | Filtering, NAT, observability, traffic shaping, redirection | Understand JSON by default |
| Scheduler, memory, fd and security subsystems | Run and constrain server processes | Define API behavior |
| TLS endpoint | Encrypt/decrypt transport payload | Validate application JSON |
| HTTP server/framework | Parse HTTP, delimit body, dispatch method/path | Implement business rules automatically |
| JSON parser/validator | Decode JSON; check syntax and configured constraints | Change how IP/TCP deliver bytes |
| Application handler | Perform requested operation and build response | Replace the underlying socket path |

## Common variations

- **Reverse proxy:** The public connection ends at nginx, Envoy, a load balancer, or another proxy. A *second* connection and request path connects proxy to application, possibly through loopback or a Unix-domain socket. The application may see proxy headers rather than the original peer address directly.
- **HTTP/2:** Multiple request streams share one TCP connection; frames are multiplexed. The OS still sees a TCP byte stream, while the HTTP/2 server separates streams and bodies.
- **HTTP/3:** QUIC runs over UDP. Linux handles UDP datagrams and socket delivery, while a user-space QUIC stack typically implements connection reliability, TLS, and stream handling. The TCP handshake, queues, and `accept()` path above do not apply.
- **Containers/network namespaces:** A container can see a different interface and route table from the host. A request may traverse a host bridge, veth pair, NAT, and multiple namespaces before the process sees it.
- **Loopback/Unix sockets:** A same-host proxy can skip the physical NIC. Unix-domain sockets also skip IP and TCP while retaining socket/syscall, HTTP, JSON, and application layers if HTTP is used over them.
- **Short-circuit responses:** Firewall drop, TCP reset, TLS failure, HTTP parse error, auth rejection, and invalid JSON can each end the request before its application handler.

## How to map a real endpoint on this machine

Run the following in the service's network namespace with suitable privileges. The host's interface, route, and listener state are visible from this shell, but the target JSON endpoint has not been identified:

```bash
ip -brief address
ip route get <client-ip>
ss -ltnp
ss -tnp '( sport = :<port> )'
systemctl status <service>
cat /proc/<server-pid>/cgroup
readlink /proc/<server-pid>/ns/net
```

Then inspect the owning process's server/proxy configuration and application route definitions. For a controlled test request, packet capture or kernel tracing can show arrival and socket activity, while application tracing shows TLS, HTTP, JSON, middleware, and handler timing. A syscall trace can reveal `accept4`, `epoll_wait`, `recvmsg`, and `sendmsg`, but it cannot by itself show which JSON fields were parsed or which HTTP route matched. Capture and traces may contain request data, so scope them to a test endpoint.

The central invariant is: **the common OS path handles packets, sockets, processes, and bytes; JSON and HTTP routes are interpretations of those bytes above the socket layer.**

## User-space execution and reachability investigation

This section applies the protocol in [EVIDENCE-DRIVEN-NEGATIVE-SPACE-GUIDE.md](EVIDENCE-DRIVEN-NEGATIVE-SPACE-GUIDE.md) to the **user-space side** of an inbound JSON request. "Disassembly" here means decomposing execution into observable transitions. There is no application-independent instruction trace: a real disassembly requires a particular binary, runtime, version, and configuration. The graph below is a testable model, not a claim that every framework takes every edge.

### Objective ledger

| Field | Current answer |
| --- | --- |
| Objective | Follow a valid JSON request through gates and transformations to a later user-space consumer and its syscall; determine separately whether a passwordless-authentication consumer is reachable. |
| Ground truth | Linux delivers socket bytes to a process; HTTP and JSON handling occur in user space. The CPython probe below demonstrates callback timing, and the final section traces a real local synthetic JSON endpoint to a worker socket. No passwordless endpoint has been identified here. |
| Current model | The request, authentication, parser, validator, handler, and downstream consumer form a directed graph. The syscall edge needs a specific producer, passing gates, transformed data, and an observed effect. |
| Key unknown | Which other application or passwordless endpoint should be tested, and what consumer follows its accepted JSON? |
| Next discriminating observation | On a selected target, compare a valid request with one changed gate and trace the first downstream syscall plus the consumer's later outcome. The findings below are **PROVEN** only for their named runtimes and synthetic service. |

### Execution graph from process entry

```text
process start
  -> loader maps executable/shared libraries; runtime initializes
  -> configuration, credentials, routes, middleware, plugins are registered
  -> listener/proxy connection is established
  -> event loop or worker receives socket bytes
  -> TLS/HTTP framing and limits
  -> method/path/header/cookie gate
       |-> rejected/redirected -> error/log/response
       `-> route and middleware selection
             -> body read / decompression / limits
             -> JSON syntax parse and object creation
             -> binding/coercion/defaults/custom hooks?
             -> schema and domain validation/custom hooks?
             -> authorization and handler dispatch
             -> DB/cache | file/storage | template | outbound HTTP | queue
             -> response/error/log/audit/async continuation
```

The ordering of route selection, authentication, body read, validation, and handler dispatch is framework- and configuration-dependent. A body may be parsed globally before routing, parsed only for a selected route, or never parsed when an earlier gate rejects the request. Error handling, logging, and audit code can run on either path. Async work may continue after the HTTP response, so the response alone does not prove the full effect.

### What a JSON value can reach

Each row is a **candidate edge**, not a finding. The gate column is the minimum fact to establish before claiming reachability.

| Candidate region | Required producer and gate | Observable distinction |
| --- | --- | --- |
| Parser/binder hooks | The selected parser/binder invokes custom constructors, setters, converters, or polymorphic type resolution for that field/type. | Trace the hook with a valid envelope and a changed field; compare decoded values and calls. |
| Validation logic | The field survives parsing and binding; a validator runs for that route. Custom validators may read state or call services. | Validator span plus dependency call; a syntax error alone cannot test this edge. |
| Authorization/policy | The request supplies data consumed by an authorization decision, and an authenticated principal/context exists where required. | Policy inputs and decision trace; distinguish 401/403 from body-validation failure. |
| Passwordless authentication | A login, challenge, callback, or session flow actually consumes the JSON or shared request context. A neighboring auth module in the same process is insufficient. | Correlated challenge/session identifier, state transition, and auth decision; check expiry, binding, and replay gates. |
| Database/cache | A handler or validator passes a value into a query, key, transaction, or cache operation. | Span/query template and safe test-state change; a successful HTTP parse is insufficient. |
| File/object storage | A reachable handler maps a value to a path, key, upload, read, or export operation. | File/storage API call and effective normalized target; JSON alone does not open a file. |
| Templates, serialization, logging | A value is rendered, serialized, formatted, or logged, including on error paths. | Output bytes or sink trace, with encoding/redaction context. |
| Outbound network or background jobs | A reachable handler schedules or performs the call and propagates the value. | Request/job trace and later consumer result; an accepted queue item is not the final effect. |
| Code execution facilities | A reachable code path explicitly uses a shell, interpreter, dynamic loader, plugin system, or equivalent with request-derived control data. | Concrete callsite, argument provenance, and execution trace; no such facility follows automatically from JSON parsing. |

**Passwordless is a family of flows, not one parser path.** A magic-link request may accept JSON to create a token, while redemption may use a URL token and cookie. A passkey flow may accept JSON carrying a challenge response and invoke credential verification. In either case, shared process memory does not bypass the flow's own challenge, origin, expiry, user binding, session, or replay checks. Those checks must be mapped as distinct gates for the chosen implementation.

For a WebAuthn assertion, the [W3C verification procedure](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) explicitly parses `clientDataJSON` and then checks its type, challenge, and origin, along with RP ID and signature. Thus a JSON HTTP envelope may lead to a **second JSON parse** inside authentication: `outer request -> assertion field decoding -> clientDataJSON parse -> verification gates -> session decision`. This is a normative flow model, **not** evidence that any application in this workspace exposes or misimplements it. The second parse is a candidate region to trace when an actual passkey endpoint is selected.

**Multi-hop effects need a second producer.** A JSON value may be stored in a file, database, cache, or job message and later read by a worker, renderer, configuration loader, or auth flow. The first request only proves the write or enqueue edge. To claim the later effect, identify the consumer, its trigger and identity, the value it actually reads after normalization, and any intervening validation. Likewise, a field that influences a filename does not imply that the file will be interpreted as code. That requires a separate, reachable loader or execution callsite.

### Negative-space method for one endpoint

1. Establish a valid, authorized baseline request and record raw HTTP bytes, decoded JSON, response, trace/call graph, and relevant state before and after. If there is no baseline, record the earliest reached gate and mark later regions **MASKED**.
2. Hold the route, credentials, session, content type, and required fields constant. Change one dimension at a time: absent/null/wrong-type/extra/nested field, value boundary, repeated request, expiry, or concurrent request. Record where the input is rejected, normalized, ignored, or forwarded.
3. Trace the divergence point between competing explanations. Use application spans or call stacks for parser/validator/handler order; use syscall tracing only for kernel crossings; use database/job/storage logs to follow later effects. An HTTP error code alone rarely identifies the rejecting layer.
4. For every proposed jump, record `producer -> gate -> callsite -> effect`, with **PROVEN**, **INFERRED**, **UNKNOWN**, or **MASKED**. A static callsite is **INFERRED** until an input is shown to reach it under stated conditions.
5. Re-run the full valid workflow after diagnostics. Confirm downstream completion and cleanup, including asynchronous work. Keep observations from instrumented runs distinct from normal operation.

An example discriminating question is: "Does a rejected JSON field reach a custom validator, or does binding reject it first?" Hold the valid request envelope fixed, change only that field, and trace both calls. If the binder rejects it, validator behavior is **MASKED** by that gate. Trying more variants that all fail binding does not provide new evidence about the validator.

### Investigation log and corrections

| Move | Evidence or observation | Correction to the model |
| --- | --- | --- |
| 1. Read the existing Linux path and the evidence guide. | The OS path ends at bytes; the guide requires producer, gate, oracle, and scoped evidence labels. | Treat JSON handling as the **research starting point** in user space, while retaining the socket/HTTP layers as earlier execution gates. |
| 2. Decompose the conventional request path. | The existing map showed JSON parsing before middleware and routing as one illustrative sequence; it also noted that frameworks vary. | Replace a single mandatory sequence with branches. Route/auth may precede body parsing; errors may enter separate handlers. |
| 3. Enumerate adjacent regions. | Parsing, binding, validation, auth, storage, logging, and async work have different prerequisites and effects. | Same process or module proximity is not reachability. Require a concrete data/control-flow edge and its gate. |
| 4. Check the passwordless example against the graph. | Magic-link and passkey flows can consume different request surfaces and state. | Do not assume a JSON login request reaches redemption or credential verification; track each flow's producer and state gates. |
| 5. Check initial proof limit. | At the time of the first map, no application binary, route, baseline request, or execution trace had been selected. | Mark application-specific candidate edges **UNKNOWN**; do not describe a vulnerability or cross-region execution as proven. |
| 6. Follow indirect effects beyond the response. | Persistence and queues create later consumers with their own triggers and gates. | Split `JSON -> write/enqueue` from `later read/consume -> effect`; an intermediate write is not proof of later execution. |
| 7. Select a concrete runtime primitive. | System CPython `3.9.25` and its `_json` native module are installed; the module exposes `_json.Scanner`. | Use this as a representative parser, while keeping production-application reachability **UNKNOWN**. |
| 8. Disassemble entry and decoder. | ELF `_start` calls libc startup, whose main target jumps to `Py_BytesMain`; `json.loads` bytecode selects a default decoder or a customized one; `raw_decode` calls `scan_once`. | A static Python fallback `JSONObject` exists, but this build's active scanner is native `_json.Scanner`; source-reading the fallback alone would misidentify the executed path. |
| 9. Probe callbacks and negative space. | `object_hook` fired for a complete nested object before a later outer JSON error; `parse_int` fired before a later error; duplicate keys collapsed by default, while `object_pairs_hook` saw both. | Whole-document failure does not imply no user callback ran. Callback configuration is a necessary gate; duplicate-key policy is parser/configuration-specific. |
| 10. Probe an actual HTTP exchange. | A loopback `POST /probe` reached `recvfrom`, route selection, body read, callback, and either validation/200 or JSON error/400. | Preserve the distinction between a controlled demonstration and a claim about an unspecified server; extra startup syscalls are not automatically request effects. |
| 11. Check a second runtime. | Node.js `v24.22.2` invoked a `JSON.parse` reviver for valid JSON but invoked none for the same malformed outer document. | Narrow the finding: parser callbacks are a possible user-code edge, but callback timing before whole-document rejection is not universal. |
| 12. Preserve a reproducible HTTP probe. | [json_request_probe.py](json_request_probe.py) reproduces the two POST outcomes and emits its handler bytecode on request. | The HTTP trace now has a runnable artifact; its route and validation logic are illustrative, not evidence about another application. |
| 13. Map a passwordless standard's inner parse. | WebAuthn assertion verification includes parsing `clientDataJSON` before challenge, origin, RP ID, and signature checks. | Separate reaching an inner JSON parser from satisfying authentication gates or creating a session. |
| 14. Inspect Node's native parse branch. | Local Node's V8 disassembly calls `ParseJson`, checks for failure, and only later calls `Internalize` for the reviver path; controlled malformed JSON invoked no reviver. | The CPython callback-before-error behavior is not portable across runtimes. A non-string input can separately invoke `toString` before Node parses. |
| 15. Disassemble a third runtime's binder. | Jackson 2.17.0 `MethodProperty.deserializeAndSet` invokes a bean setter through reflection at Java bytecode offset 108; controlled malformed outer JSON and duplicate keys reached the setter. | A binder can enter application methods before complete-document acceptance, but only when the selected target type and property use such a setter. |

### Performed disassembly: CPython JSON boundary

**Target and limits.** The representative runtime is `/usr/bin/python3.9` (`python3-3.9.25-1.amzn2023.0.11.x86_64`) with `/usr/lib64/python3.9/lib-dynload/_json.cpython-39-x86_64-linux-gnu.so`. This is the local Amazon Linux build, not an Ubuntu binary or a target application. The extension is stripped of private function symbols, so instruction addresses alone cannot name each parser helper. CPython's pinned [3.9.25 `_json.c` source](https://github.com/python/cpython/blob/v3.9.25/Modules/_json.c) and runtime traces supply the function-level correspondence; the local binary and bytecode are the direct disassembly evidence.

| Boundary | Direct observation | Conclusion |
| --- | --- | --- |
| ELF entry | `readelf` reports entry `0x1070`; `objdump` shows `_start` calling `__libc_start_main`, with the main target at `0x1160` jumping to `Py_BytesMain@plt`. | **PROVEN:** this interpreter enters CPython through `Py_BytesMain`; the particular HTTP program is then run by the interpreter. |
| Python JSON entry | `dis.dis(json.loads)` shows a default-decoder fast path and a branch that constructs `JSONDecoder` when hooks/options are supplied. `dis.dis(JSONDecoder.raw_decode)` calls `self.scan_once`. | **PROVEN:** hook configuration changes the decoder path before the scan begins. |
| Probe handler bytecode | `python3 json_request_probe.py --disassemble` shows `Handler.do_POST` using `CALL_FUNCTION_KW` for `json.loads(body, object_hook=...)`, then a `JSONDecodeError` branch before the later validation block. | **PROVEN for probe:** the handler's own control flow puts application validation after parsing, while parser callbacks may run inside the call. |
| Native parser | `json.scanner.make_scanner` is `_json.Scanner`; the default decoder's `scan_once` is an `_json.Scanner` instance. The extension imports Python call machinery and CPython source calls `PyObject_CallOneArg` for configured hooks after a complete object. | **PROVEN:** the controlled run uses the native scanner and can re-enter Python callbacks during parsing. Exact private machine-code offsets are **UNKNOWN** because this extension is stripped. |
| Valid request | The loopback probe sent `POST /probe` with `{"a":{}}`. The recorded sequence was `route -> body_bytes(8) -> object_hook({}) -> object_hook({"a":{}}) -> validation(True) -> 200`. `strace -f -e trace=network` observed `socket`, `bind`, `listen`, `connect`, `accept4`, `sendto`, and `recvfrom`. | **PROVEN for probe:** callback code ran before the handler's validation step. |
| Invalid outer document | The same probe sent `{"a":{},` with the same route and headers. The sequence was `route -> body_bytes(8) -> object_hook({}) -> JSONDecodeError -> 400`; the validation step did not run. | **PROVEN for probe:** a parser callback can run even though the whole JSON body is ultimately rejected. |

Minimal reproducer of the distinguishing parser behavior:

```python
import json

events = []
try:
    json.loads('{"a":{},', object_hook=lambda obj: events.append(obj) or obj)
except json.JSONDecodeError:
    pass
assert events == [{}]
```

The complete [loopback HTTP probe](json_request_probe.py) can be rerun without opening a public listener:

```bash
python3 json_request_probe.py
python3 json_request_probe.py --disassemble
strace -f -e trace=network python3 json_request_probe.py
```

The probe binds `127.0.0.1` on an ephemeral port. `strace` also captures process startup and client-side calls (including unrelated name-service attempts), so attribute syscalls by process, descriptor, and timing before calling one a server-side request effect.

Additional controlled negatives: `{"a":` failed before any completed object could invoke `object_hook`; `{"n":7,` invoked a configured `parse_int` before the later syntax error; a callback-raised `RuntimeError` propagated out of `json.loads`. With both object hooks configured, `object_pairs_hook` took priority. Default `json.loads('{"role":"a","role":"b"}')` returned the final value (`"b"`), while `object_pairs_hook` received both pairs. Default `json.loads('{"v":NaN}')` accepted `NaN` as a float. These are parser observations, not evidence of an authentication bypass or external effect.

**Cross-runtime native check.** In local Node.js `v24.22.2` (V8 `13.6.233.17-node.63`), `JSON.parse('{"a":{}}', reviver)` invoked the reviver for `a` and then the root; `JSON.parse('{"a":{},', reviver)` raised `SyntaxError` with **no** reviver calls. `objdump` of the local Node executable shows `JsonParser<unsigned char>::Parse` calling `ParseJson` at `0x10b9310`, testing its result at `0x10b9318`, branching on failure at `0x10b931b`, and calling `JsonParseInternalizer::Internalize` at `0x10b93f7` only on the continuing path. This agrees with [Node's pinned V8 source](https://github.com/nodejs/node/blob/v24.22.2/deps/v8/src/json/json-parser.h#L165-L181). The addresses identify this local binary only.

A separate pre-parse edge exists when the caller supplies a **non-string object** to `JSON.parse`: `JSON.parse({toString(){ return '{"a":{},'; }}, reviver)` invoked `toString`, then raised `SyntaxError` without invoking the reviver. This follows the [JSON.parse builtin's input conversion](https://github.com/nodejs/node/blob/v24.22.2/deps/v8/src/builtins/builtins-json.cc). An ordinary HTTP body already passed as a string does not create that edge; an application wrapper would have to pass an object.

**Third-runtime bytecode check.** Local Java 21 with Jackson 2.17.0 provides a different user-code edge. `javap -c -p com.fasterxml.jackson.databind.deser.impl.MethodProperty` shows `deserializeAndSet` invoking its `_valueDeserializer` and then, at bytecode offset `108`, `java.lang.reflect.Method.invoke` on `_setter`. The [pinned Jackson source](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.17.0/src/main/java/com/fasterxml/jackson/databind/deser/impl/MethodProperty.java) supports that call path. In a controlled `ObjectMapper.readValue` into a bean with `setX(int)`, `{"inner":{"x":1}}` called `setX(1)` and succeeded; `{"inner":{"x":2},` called `setX(2)` before `JsonParseException`; `{"x":1,"x":2}` called `setX(1)` and `setX(2)`. An earlier failure at `{"x":` called no setter. These are **PROVEN** for bean binding with that setter, not for tree parsing or an arbitrary target type.

To reproduce the Jackson check with the local jars:

```bash
jackson_cp="$HOME/.m2/repository/com/fasterxml/jackson/core/jackson-core/2.17.0/jackson-core-2.17.0.jar:$HOME/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.17.0/jackson-databind-2.17.0.jar:$HOME/.m2/repository/com/fasterxml/jackson/core/jackson-annotations/2.17.0/jackson-annotations-2.17.0.jar"
/tmp/resident-jvm-runtime/usr/lib/jvm/java-21-amazon-corretto.x86_64/bin/javap -c -p -classpath "$jackson_cp" com.fasterxml.jackson.databind.deser.impl.MethodProperty
/tmp/resident-jvm-runtime/usr/lib/jvm/java-21-amazon-corretto.x86_64/bin/jshell -q --class-path "$jackson_cp"
```

Enter the following in JShell:

```java
import com.fasterxml.jackson.databind.*;
class Bean { public int x; public void setX(int n) { System.out.println("SETTER " + n); x = n; } }
var mapper = new ObjectMapper();
mapper.readValue("{\"x\":1,\"x\":2}", Bean.class);
```

The two setter calls are an observable branch into application code. This experiment did not implement file handling, authentication, or any other external effect.

| Runtime and configured edge | Valid completed object | Malformed outer document after completed child | Duplicate key behavior observed |
| --- | --- | --- | --- |
| CPython 3.9.25 `object_hook` | Hook runs during scanning | Child hook runs before error | Default dict keeps final value; `object_pairs_hook` can see both pairs |
| Node 24.22.2 `JSON.parse` reviver | Reviver runs after successful parse | No reviver call | Final value is passed once to reviver |
| Jackson 2.17.0 bean setter | Setter runs during binding | Completed child setter runs before error | Setter runs for each occurrence |

This comparison concerns the specific callback/binding configurations shown. It does not assert that every JSON endpoint installs such hooks or binds into a bean.

**Parser-boundary result.** The controlled CPython HTTP probe **PROVES** `request bytes -> JSON scanner -> configured callback`, including for a request that receives 400. Jackson separately **PROVES** `JSON field -> bean setter` before outer-document acceptance in its selected binding mode. Node **PROVES** a different order for its reviver. Those facts do not themselves establish an edge to passwordless authentication, file handling, a loader, or code execution. The next section follows a concrete accepted request out of JSON handling and into a syscall.

## Concrete indirect path: JSON to worker socket

The [source investigation](https://a13xp0p0v.github.io/2026/11/02/CVE-2026-31695.html) behind the evidence guide follows an observed primitive through exact bytes, later consumers, and a policy that initially blocked the desired effect. Applied here, the useful question is: **after valid JSON passes this service's gates, which component receives which bytes, and what syscall does that handoff require?** The following case is an owned, loopback-only synthetic exchange replica. It is a concrete example of the method, not a claim about other applications or a passwordless implementation.

### Producer, gates, and effect

```text
signed POST /api/v3/wallet/withdraw with JSON body
  -> HttpServer reads raw body (bounded at 65,536 bytes)
  -> rate limit and route permission
  -> Auth.allowed verifies HMAC over timestamp + method + path + RAW body
  -> Jackson reads body into Map<String,Object>
  -> withdrawal field, destination, amount, hold, and idempotency gates
  -> Jackson serializes the accepted Map back to JSON bytes
  -> RuntimeMaterials.sign in explicitly selected WORKER mode
  -> Java Socket.connect to a separate loopback worker  [observed syscall]
  -> worker verifies its own message MAC, freshness, nonce, and JSON policy
  -> worker signs bytes; owner records digest and stores synthetic result
  -> HTTP response returns clientWithdrawId
```

The route order is visible in [Replica.java](weex-research/replica/src/main/java/research/weex/backend/Replica.java): `auth.allowed` receives the raw body **before** `json.readValue`; the withdrawal branch validates fields and checks `existingWithdrawal` **before** `materials.sign(json.writeValueAsBytes(body))`. [RuntimeMaterials.java](weex-research/replica/src/main/java/research/weex/synthetic_wallet/RuntimeMaterials.java) shows that a `Socket.connect` occurs only in its configured `WORKER`/`EXTERNAL` modes; the default no-material mode hashes locally. [PersistentSigningWorker.java](weex-research/replica/src/main/java/research/weex/synthetic_wallet/PersistentSigningWorker.java) has a second authentication/policy boundary and parses the forwarded JSON in a separate process. The local example uses HMAC API authentication, **not** passwordless authentication.

### Controlled observation

The [isolated probe](json_to_syscall_probe.py) starts fresh owner and worker processes on ephemeral loopback ports, selects `WORKER` mode, signs requests with synthetic credentials, traces the owner's `connect`/`accept4` calls, and terminates both processes. It does not send requests to the pre-existing Java listener.

The worker process and `WORKER` mode are **preconditions supplied by the probe/operator**, not effects of the JSON request. `RuntimeMaterials.controlLoop` accepts `LOAD WORKER` from the service's stdin control channel; the HTTP route has no branch that loads that mode or starts a process. This distinction is necessary before attributing the later socket call to request control.

| Request, in test order | HTTP status | Cumulative owner-to-worker `connect` count | Reached effect |
| --- | ---: | ---: | --- |
| Valid JSON, no API signature | 401 | 0 | Stopped before JSON parse/worker handoff |
| Signed JSON, disallowed destination | 400 | 0 | Parsed but stopped in route validation |
| Signed valid JSON with harmless whitespace | 200 | 1 | Connected to worker and completed signing |
| Same valid body and business ID again | 200 | 1 | Idempotency returned prior result without another worker call |

The traced `connect` used `AF_INET6` with `::ffff:127.0.0.1` and returned `EINPROGRESS`, which is normal for the nonblocking connection attempt observed here. The HTTP 200 plus the worker-derived digest establish that the exchange completed; the `connect` return alone would not.

The API signature covered the **raw whitespace-bearing body**. The owner then parsed and reserialized it before forwarding. The probe compared the owner's `CONTROL DIGEST` value with `SHA256(HMAC(worker_key, bytes))`: it matched the compact reserialized JSON and did **not** match the raw HTTP bytes. Thus the first authenticated byte sequence and the worker's signed byte sequence differ in this controlled case. That is a measured transformation boundary, not an inferred one from source alone.

Run `python3 json_to_syscall_probe.py` from this directory to reproduce the four statuses, cumulative connect counts, and digest comparisons. The trace file is temporary and contains only connection syscalls; the script prints the relevant line and removes the trace when done.

### Corrections made during this trace

| Initial reading | Contradicting evidence | Corrected model |
| --- | --- | --- |
| Zero worker connects suggested the branch was not reached. | Valid request returned 200, but the trace filter searched only `sin_port`; Java used `sin6_port` with an IPv4-mapped IPv6 address. | Filter by the actual worker port across address families. The corrected per-request count is `0, 0, 1, 1`. |
| The response should expose a signature digest to compare bytes. | The route returns only `clientWithdrawId`, so response lookup produced `null`. | Read the owner's synthetic `CONTROL DIGEST` after the request; it matches the reserialized-body prediction. |
| A successful `connect` line alone would prove the worker completed. | The syscall returned `EINPROGRESS`. | Use the completed HTTP result and matching worker signature digest as the later-effect oracle. |

**Scoped conclusion:** this service proves an indirect path `valid JSON -> route validation -> reserialization -> worker-mode signer -> loopback connect -> separate consumer`. It does **not** prove file execution, a passwordless-authentication transition, or any path beyond this synthetic service. A validator can itself perform I/O in some applications; in this specific route, the observed socket exit occurs after validation through `materials.sign`. For a different application, the equivalent investigation starts with its valid request and follows the actual transformed value to its next consumer and syscall.

### Criticality check

The traced `connect` is a **baseline of intended functionality**, not a security finding. For a vulnerability claim, the investigation must show an unintended crossing: a producer lacking the required authority reaches the effect; accepted data changes meaning across a security boundary; a downstream consumer accepts something the policy forbids; or a request causes an effect outside the documented operation. The tests here showed none of those outcomes. The unsigned request was denied before parsing, the invalid destination was denied before worker contact, and the repeated business ID did not cause another signing operation. The raw/serialized byte difference was measured, but the owner validates and forwards the same parsed map; no conflicting security decision was observed.

The remaining high-value question is **not** whether valid JSON can cause a syscall. It is whether a particular application lets lower-trust JSON control a security-relevant consumer or operation beyond the authority granted by its route. This local synthetic service does not supply a passwordless-authentication endpoint to test that question.

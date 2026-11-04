/*
 * Replica.java -- TARGET-REPLICA #1 (reconstructed from the invariants documented
 * in LINUX_JSON_REQUEST_PATH.md, "Concrete indirect path" section).
 *
 * This is NOT the original weex-research replica (that tree is missing from this
 * snapshot; see MISSING-EVIDENCE-REGISTER). It reproduces only the documented
 * component boundaries and their stated invariants:
 *
 *   HttpServer(raw body) -> HMAC-auth over RAW bytes -> Jackson parse to Map
 *   -> field validation + idempotency -> Jackson reserialize -> signer->worker
 *
 * Security-sensitive operations (target-first inventory):
 *   S1 auth.allowed      : authorization decision over raw request bytes
 *   S2 validateWithdrawal: business gate over parsed map (destination allow-list)
 *   S3 idempotencyStore  : persistent state transition keyed by bizId
 *   S4 forwardToWorker   : outbound socket write of RESERIALIZED bytes
 *
 * Instrumentation prints each component's VIEW of the same logical request so
 * cross-component disagreements are directly observable. No production behavior
 * was modified; this file is new synthetic scaffolding.
 */
package research.target;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Replica {
    static final int HTTP_PORT = Integer.getInteger("httpPort", 18080);
    static final int WORKER_PORT = Integer.getInteger("workerPort", 18081);
    static final byte[] API_KEY = "synthetic-api-key".getBytes(StandardCharsets.UTF_8);
    static final Set<String> ALLOWED_DEST = Set.of("ledger", "audit");
    static final ObjectMapper json = new ObjectMapper();
    static final Map<String, String> idem = new java.util.concurrent.ConcurrentHashMap<>();

    public static void main(String[] a) throws Exception {
        startWorker();               // separate consumer: MACs the bytes it receives
        new Thread(Replica::serveHttp).start();
    }

    // ---- worker: proves what bytes actually crossed the boundary ----
    static void startWorker() throws Exception {
        ServerSocket ws = new ServerSocket(WORKER_PORT, 16, InetAddress.getByName("127.0.0.1"));
        new Thread(() -> {
            while (true) try (Socket s = ws.accept()) {
                byte[] buf = s.getInputStream().readAllBytes();
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(new SecretKeySpec("worker-key".getBytes(), "HmacSHA256"));
                System.out.println("[WORKER] recv_bytes=" + new String(buf, StandardCharsets.ISO_8859_1)
                    + " mac_over_recv=" + hex(m.doFinal(buf)));
            } catch (Exception e) {}
        }).start();
    }

    static void serveHttp() {
        try (ServerSocket ss = new ServerSocket(HTTP_PORT, 16, InetAddress.getByName("127.0.0.1"))) {
            while (true) {
                Socket s = ss.accept();
                new Thread(() -> handle(s)).start();
            }
        } catch (IOException e) { e.printStackTrace(); }
    }

    static String hmac(byte[] key, String msg) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return hex(m.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }
    static String hex(byte[] b) { StringBuilder sb=new StringBuilder(); for(byte x:b) sb.append(String.format("%02x",x)); return sb.toString(); }

    static void handle(Socket s) {
        try (s; DataInputStream in = new DataInputStream(s.getInputStream());
             OutputStream out = s.getOutputStream()) {
            String line = in.readLine();
            if (line == null) return;
            String hdr; StringBuilder rawHdr = new StringBuilder(line).append("\n");
            int clen = 0; String sig = "", ts = "";
            while ((hdr = in.readLine()) != null && !hdr.isEmpty()) {
                rawHdr.append(hdr).append("\n");
                String lo = hdr.toLowerCase();
                if (lo.startsWith("content-length:")) clen = Integer.parseInt(hdr.split(":")[1].trim());
                if (lo.startsWith("x-signature:")) sig = hdr.split(":",2)[1].trim();
                if (lo.startsWith("x-timestamp:")) ts = hdr.split(":",2)[1].trim();
            }
            byte[] bodyBytes = in.readNBytes(clen);
            String rawBody = new String(bodyBytes, StandardCharsets.UTF_8);
            String method = line.split(" ")[0], path = line.split(" ")[1];

            // S1: AUTH OVER RAW BYTES
            String preimage = ts + method + path + rawBody;
            boolean authed = sig.equals(hmac(API_KEY, preimage));
            System.out.println("[S1-AUTH] over_raw_len=" + rawBody.length() + " authed=" + authed);
            if (!authed) { resp(out, 401, "{\"error\":\"auth\"}"); return; }

            // PARSE: Jackson into Map (documented mode: readValue into Map)
            Map<String,Object> body;
            try { body = json.readValue(bodyBytes, Map.class); }
            catch (Exception e) { System.out.println("[PARSE] reject " + e.getClass().getSimpleName()); resp(out, 400, "{\"error\":\"json\"}"); return; }
            System.out.println("[PARSE] dest_view=" + body.get("dest") + " amount_view=" + body.get("amount"));

            // S2: VALIDATION OVER PARSED MAP
            Object dest = body.get("dest"), amt = body.get("amount"), biz = body.get("bizId");
            if (dest == null || !ALLOWED_DEST.contains(dest.toString())) {
                System.out.println("[S2-VALIDATE] reject dest=" + dest); resp(out, 400, "{\"error\":\"dest\"}"); return;
            }
            if (!(amt instanceof Number)) { resp(out, 400, "{\"error\":\"amount\"}"); return; }

            // S3: IDEMPOTENCY STATE TRANSITION
            String key = String.valueOf(biz);
            String prior = idem.putIfAbsent(key, "PENDING");
            if (prior != null) { System.out.println("[S3-IDEM] hit key=" + key + " -> no forward"); resp(out, 200, "{\"idempotent\":true}"); return; }

            // S4: RESERIALIZE + FORWARD (bytes differ from authenticated bytes)
            byte[] fwd = json.writeValueAsBytes(body);
            System.out.println("[S4-FORWARD] raw_authed_bytes=" + hex(bodyBytes));
            System.out.println("[S4-FORWARD] reserialized_bytes=" + hex(fwd));
            try (Socket w = new Socket("127.0.0.1", WORKER_PORT)) { w.getOutputStream().write(fwd); }
            idem.put(key, "DONE");
            resp(out, 200, "{\"clientWithdrawId\":\"" + key + "\"}");
        } catch (Exception e) { /* ignore */ }
    }

    static void resp(OutputStream o, int code, String body) throws IOException {
        String r = "HTTP/1.1 " + code + " X\r\nContent-Type: application/json\r\nContent-Length: "
            + body.length() + "\r\nConnection: close\r\n\r\n" + body;
        o.write(r.getBytes(StandardCharsets.UTF_8));
    }
}

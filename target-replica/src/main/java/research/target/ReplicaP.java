/*
 * ReplicaP -- Phase 2 variant: dual-view consumer target-replica.
 * Gate reads the FIRST occurrence of each field (streaming token scan,
 * a memory-saving choice a real service might make). Forward path uses
 * Jackson's Map view (LAST occurrence wins) and reserializes it.
 * Both views come from the SAME parser library (Jackson 2.17.0) -- this is
 * not two parsers, it is one parser consumed two ways by two components.
 */
package research.target;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.*;
import java.io.*; import java.net.*; import java.nio.charset.StandardCharsets;
import java.util.*; import javax.crypto.Mac; import javax.crypto.spec.SecretKeySpec;

public class ReplicaP {
    static final int HTTP_PORT = Integer.getInteger("httpPort", 18092);
    static final int WORKER_PORT = Integer.getInteger("workerPort", 18093);
    static final byte[] API_KEY = "synthetic-api-key".getBytes(StandardCharsets.UTF_8);
    static final Set<String> ALLOWED_DEST = Set.of("ledger","audit");
    static final ObjectMapper json = new ObjectMapper();
    public static void main(String[] a) throws Exception {
        ServerSocket ws = new ServerSocket(WORKER_PORT,16,InetAddress.getByName("127.0.0.1"));
        new Thread(()->{ while(true) try(Socket s=ws.accept()){
            byte[] buf=s.getInputStream().readAllBytes();
            System.out.println("[WORKER-P] recv="+new String(buf,StandardCharsets.ISO_8859_1));
        }catch(Exception e){} }).start();
        try(ServerSocket ss=new ServerSocket(HTTP_PORT,16,InetAddress.getByName("127.0.0.1"))){
            System.out.println("[OWNER-P] listening "+HTTP_PORT);
            while(true){ Socket s=ss.accept(); new Thread(()->handle(s)).start(); }
        }
    }
    static String hmac(byte[] k,String m)throws Exception{Mac x=Mac.getInstance("HmacSHA256");x.init(new SecretKeySpec(k,"HmacSHA256"));StringBuilder sb=new StringBuilder();for(byte b:x.doFinal(m.getBytes()))sb.append(String.format("%02x",b));return sb.toString();}
    // first-occurrence pairs view via streaming tokens
    static Map<String,String> firstPairs(byte[] body) throws IOException {
        Map<String,String> first = new LinkedHashMap<>();
        JsonParser p = json.getFactory().createParser(body);
        if (p.nextToken()!=JsonToken.START_OBJECT) { p.close(); return first; }
        while (p.nextToken()==JsonToken.FIELD_NAME) {
            String f = p.getText();
            JsonToken vt = p.nextToken();
            String v;
            if (vt==JsonToken.VALUE_STRING) v=p.getText();
            else if (vt!=null && vt.isScalarValue()) v=p.getValueAsString();
            else { v="<non-scalar>"; p.skipChildren(); }
            first.putIfAbsent(f,v);   // FIRST occurrence wins
        }
        p.close();
        return first;
    }
    static void handle(Socket s){
        try(s;DataInputStream in=new DataInputStream(s.getInputStream());OutputStream out=s.getOutputStream()){
            String line=in.readLine(); if(line==null)return;
            String hdr; int clen=0; String sig="",ts="";
            while((hdr=in.readLine())!=null&&!hdr.isEmpty()){
                String lo=hdr.toLowerCase();
                if(lo.startsWith("content-length:"))clen=Integer.parseInt(hdr.split(":")[1].trim());
                if(lo.startsWith("x-signature:"))sig=hdr.split(":",2)[1].trim();
                if(lo.startsWith("x-timestamp:"))ts=hdr.split(":",2)[1].trim();
            }
            byte[] bodyBytes=in.readNBytes(clen);
            String rawBody=new String(bodyBytes,StandardCharsets.UTF_8);
            String[] rl=line.split(" ");
            boolean authed=sig.equals(hmac(API_KEY,ts+rl[0]+rl[1]+rawBody));
            System.out.println("[S1-AUTH-P] authed="+authed+" raw_len="+rawBody.length());
            if(!authed){resp(out,401,"{}");return;}
            Map<String,String> pairs=firstPairs(bodyBytes);
            // ORDER-INDEPENDENT duplicate policy: last-wins (same as a dict view)
            Map<String,Object> map=json.readValue(bodyBytes, new com.fasterxml.jackson.core.type.TypeReference<LinkedHashMap<String,Object>>(){});
            // canonicalization removes insertion-order information from the object model
            Map<String,Object> sorted=new TreeMap<>(map);
            System.out.println("[PAIRS] dest_first="+pairs.get("dest")+" amount_first="+pairs.get("amount"));
            System.out.println("[MAP]   dest_last="+map.get("dest")+" amount_last="+map.get("amount"));
            boolean pairsOk = pairs.get("dest")!=null && ALLOWED_DEST.contains(pairs.get("dest"));
            boolean mapOk   = map.get("dest")!=null && ALLOWED_DEST.contains(map.get("dest").toString());
            System.out.println("[GATE] pairs_allow="+pairsOk+" map_allow="+mapOk+" DISAGREE="+(pairsOk!=mapOk));
            // realistic pattern: gate checks ONLY its own (pairs) view
            if(!pairsOk){resp(out,400,"{\"error\":\"dest\"}");return;}
            byte[] fwd=json.writeValueAsBytes(sorted);
            System.out.println("[S4-FORWARD-P] forwarded="+new String(fwd,StandardCharsets.ISO_8859_1));
            try(Socket w=new Socket("127.0.0.1",WORKER_PORT)){w.getOutputStream().write(fwd);}
            resp(out,200,"{\"ok\":true}");
        }catch(Exception e){System.out.println("[ERR] "+e);}
    }
    static void resp(OutputStream o,int c,String b)throws IOException{
        o.write(("HTTP/1.1 "+c+" X\r\nContent-Length: "+b.length()+"\r\nConnection: close\r\n\r\n"+b).getBytes());
    }
}

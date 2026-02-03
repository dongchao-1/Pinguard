# Pinguard

$env:RUST_LOG="debug"; cargo run
sslocal -s 127.0.0.1:8388 -b 127.0.0.1:1080 -k "my_strong_password" -m "chacha20-ietf-poly1305"
curl.exe -x socks5h://127.0.0.1:1080 https://ipinfo.io

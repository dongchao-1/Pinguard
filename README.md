# Pinguard

# 测试
```
$env:RUST_LOG="debug"; cargo run
sslocal -s 127.0.0.1:8388 -b 127.0.0.1:1080 -k "my_strong_password" -m "chacha20-ietf-poly1305"
curl.exe -x socks5h://127.0.0.1:1080 https://ipinfo.io
```

# 交叉编译
```
# https://github.com/rust-cross/rust-musl-cross
docker run --rm -v "${PWD}:/home/rust/src" -w /home/rust/src ghcr.io/rust-cross/rust-musl-cross:aarch64-musl cargo build --release
```

# 传到服务器
```
scp target/aarch64-unknown-linux-musl/release/pinguard wrt:/opt/pinguard
```

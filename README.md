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

# init.d
/etc/init.d/pinguard
```
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

# 你的程序所在路径
PROG=/opt/pinguard/pinguard

start_service() {
    procd_open_instance

    procd_set_param env TZ="CST-8"

    procd_set_param command "$PROG"

    # 【核心】开启保活：如果挂了，自动重启
    # respawn threshold timeout retry
    # 3600: 如果程序运行超过3600秒挂了，视为意外崩溃，立即重启
    # 5: 如果重启后5秒内又挂了，就不无限重启了，防止死循环卡死系统
    # 0: 无限重试次数
    procd_set_param respawn 3600 5 0

    # 把程序的日志（println!的内容）重定向到系统日志 (logread)
    procd_set_param stdout 1
    procd_set_param stderr 1

    procd_close_instance
}
```

启动服务
```
chmod +x /etc/init.d/pinguard
/etc/init.d/pinguard enable   # 设置开机自启
/etc/init.d/pinguard start
/etc/init.d/pinguard status
/etc/init.d/pinguard stop
nohup /etc/init.d/pinguard restart >/dev/null 2>&1 &
```

查看日志
```
logread -f -e pinguard
logread -e pinguard
```

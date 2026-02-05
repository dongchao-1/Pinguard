use std::io::Write;
use std::{collections::BTreeSet, str::FromStr};
use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use std::path::Path;
use std::time::Duration;
use std::sync::{LazyLock, RwLock};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use log::{error, info, warn, debug};
use reqwest::Client as reqwestClient;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use shadowsocks_service::{
    config::{Config, ConfigType, ServerInstanceConfig},
    run_server,
    shadowsocks::{
        config::ServerConfig,
        crypto::CipherKind,
    },
};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use moka::future::Cache;

fn init_logger() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    .format(|buf, record| {
        let file = record.file().unwrap_or("unknown");
        let line = record.line().unwrap_or(0);
        let thread_id = std::thread::current().id();
        let style = buf.default_level_style(record.level());

        writeln!(
            buf,
            "{} [{style}{}{style:#}] ({}:{}) [{:?}] - {}",
            buf.timestamp(),
            record.level(),
            file,
            line,
            thread_id,
            record.args(),
            style = style 
        )
    }).init();
}

#[derive(Serialize, Deserialize, Debug)]
struct PinguardConfig {
    public_ip: String,
    public_port: u16,

    ss_internal_port: u16, // TODO 随机端口？还是能不要端口？
    ss_password: String,
    ss_method: String,

    ntfy_req_topic: String,
    ntfy_resp_topic: String,

    whitelist: BTreeSet<IpAddr>,
}

impl PinguardConfig {
    fn load() -> Self {
        confy::load_path(Path::new("./pinguard.yaml")).unwrap()
    }

    fn get_public_ip(&self) -> String {
        self.public_ip.clone()
    }

    fn get_public_port(&self) -> u16 {
        self.public_port
    }

    fn get_ss_internal_port(&self) -> u16 {
        self.ss_internal_port
    }

    fn get_ss_password(&self) -> String {
        self.ss_password.clone()
    }

    fn get_ss_method(&self) -> CipherKind {
        CipherKind::from_str(&self.ss_method).unwrap()
    }

    fn get_ntfy_req_topic(&self) -> String {
        self.ntfy_req_topic.clone()
    }

    fn get_ntfy_resp_topic(&self) -> String {
        self.ntfy_resp_topic.clone()
    }

    fn check_ip(&self, ip: &IpAddr) -> bool {
        self.whitelist.contains(ip)
    }

    fn add_ip(&mut self, ip: &IpAddr) {
        self.whitelist.insert(*ip);
        confy::store_path("./pinguard.yaml", self).unwrap()
    }

    fn del_ip(&mut self, ip: &IpAddr) {
        self.whitelist.remove(ip);
        confy::store_path("./pinguard.yaml", self).unwrap()
    }
}

impl ::std::default::Default for PinguardConfig {
    fn default() -> Self {
        Self {
            public_ip: "0.0.0.0".to_string(),
            public_port: 8388,
            ss_internal_port: 10999,
            ss_password: Uuid::new_v4().to_string(),
            ss_method: "chacha20-ietf-poly1305".to_string(),
            ntfy_req_topic: format!("req-{}", Uuid::new_v4()),
            ntfy_resp_topic: format!("resp-{}", Uuid::new_v4()),
            whitelist: BTreeSet::new(),
        }
    }
}

static CONFIG: LazyLock<RwLock<PinguardConfig>> =
    LazyLock::new(|| RwLock::new(PinguardConfig::load()));

async fn get_ip_location(ip: &str) -> String {
    let url = format!("http://ip-api.com/json/{}?lang=zh-CN", ip);

    let response = match reqwest::get(&url).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("获取ip归属地，网络请求出错: {}", e);
            return "网络请求出错".to_string();
        }
    };

    let json: Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("获取ip归属地，JSON解析出错: {}", e);
            return "JSON解析出错".to_string();
        }
    };

    if json["status"].as_str() != Some("success") {
        warn!("获取ip归属地，status错误: {}", json["status"]);
        return "status错误".to_string();
    }

    let country = json["country"].as_str().unwrap_or("未知");
    let city = json["city"].as_str().unwrap_or("未知");

    format!("{}-{}", country, city)
}

static NOTIFICATION_CACHE: LazyLock<Cache<IpAddr, ()>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(30 * 60))
        .max_capacity(10_000)
        .build()
});

async fn send_auth_notification(ip: &str) -> Result<()> {
    info!("开始发送ntfy认证消息: {}", ip);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5)) // 5秒超时
        .build()?;

    let resp_url = format!("https://ntfy.sh/{}", &CONFIG.read().unwrap().get_ntfy_resp_topic());
    let actions = serde_json::json!([
        {
            "action": "http",
            "label": "✅ 允许访问",
            "url": resp_url,
            "method": "POST",
            "body": serde_json::json!({"action": "USER_ALLOWED", "ip": ip}).to_string()
        },
        {
            "action": "http",
            "label": "❌ 拒绝访问",
            "url": resp_url,
            "method": "POST",
            "body": serde_json::json!({"action": "USER_DENIED", "ip": ip}).to_string()
        }
    ]);

    let ip_loc = get_ip_location(ip).await;

    let req_url = format!("https://ntfy.sh/{}", &CONFIG.read().unwrap().get_ntfy_req_topic());
    let resp = client
        .post(&req_url)
        .header("Title", "服务器登录请求")
        .header("Priority", "high")
        .header("Tags", "warning,shield")
        .header("Actions", actions.to_string())
        .body(format!(
            "检测到 IP: {}({}) 请求访问，是否允许？",
            ip, ip_loc
        ))
        .send()
        .await?
        .text()
        .await?;
    debug!("发送结果: {}", resp);
    info!("通知已发送: {}", ip);
    Ok(())
}

async fn start_ntfy_service() {
    info!("开始监听ntfy消息");
    let client = reqwestClient::new();
    let resp_url = format!("https://ntfy.sh/{}/json", &CONFIG.read().unwrap().get_ntfy_resp_topic());

    loop {
        let resp_result = client.get(&resp_url).send().await;
        match resp_result {
            Ok(resp) => {
                info!("已连接到 ntfy，正在监听...");
                let mut stream = resp.bytes_stream();
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(bytes) => {
                            let text = String::from_utf8_lossy(&bytes);
                            for line in text.lines() {
                                if line.trim().is_empty() {
                                    continue; // 跳过空行（心跳）
                                }
                                match serde_json::from_str::<Value>(line) {
                                    Ok(json) => {
                                        handle_message(&json);
                                    }
                                    Err(e) => {
                                        warn!("收到消息，解析json错误: {}, 原文: {}", e, line)
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("读取流数据出错: {}", e);
                            break;
                        }
                    }
                }
                info!("连接已断开 (Stream ended)");
            }
            Err(e) => {
                error!("连接 ntfy 失败: {}", e);
            }
        }

        info!("5秒后尝试重连...");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

fn handle_message(json: &Value) {
    if json["event"] != "message" {
        return;
    }

    if let Some(msg_body) = json["message"].as_str() {
        match serde_json::from_str::<Value>(msg_body) {
            Ok(j) => {
                if j["action"] == "USER_ALLOWED" {
                    let new_ip = IpAddr::from_str(j["ip"].as_str().unwrap()).unwrap();
                    info!("收到允许访问通知: {}", new_ip);
                    CONFIG.write().unwrap().add_ip(&new_ip);
                } else if j["action"] == "USER_DENIED" {
                    let new_ip = IpAddr::from_str(j["ip"].as_str().unwrap()).unwrap();
                    info!("收到拒绝访问通知: {}", new_ip);
                    CONFIG.write().unwrap().del_ip(&new_ip);
                } else {
                    warn!("action不合法: {}", j["action"])
                }
            }
            Err(e) => {
                warn!("handle_message，解析json错误: {}, 原文: {}", e, msg_body)
            }
        }
    }
}

async fn start_ss_service() -> Result<()> {
    let internal_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, CONFIG.read().unwrap().get_ss_internal_port()));
    info!("启动Shadowsocks: {}", internal_addr);

    let server_config = ServerConfig::new(internal_addr,
        CONFIG.read().unwrap().get_ss_password(), CONFIG.read().unwrap().get_ss_method())?;
    // server_config.set_mode(shadowsocks_service::config::Mode::TcpOnly);
    let instance = ServerInstanceConfig::with_server_config(server_config);
    let mut config = Config::new(ConfigType::Server);
    config.server.push(instance);

    run_server(config).await?;
    info!("ss 服务启动成功");
    Ok(())
}

async fn handle_client(mut client_socket: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    let ip = peer_addr.ip();
    debug!("新链接，ip: {}", ip);

    if !CONFIG.read().unwrap().check_ip(&ip) {
        warn!("未授权IP，通知用户: {}", ip);
        let entry = NOTIFICATION_CACHE.entry(ip)
            .or_insert(())
            .await;
        if entry.is_fresh() {
            info!("获得发送锁，通知用户: {}", ip);
            if let Err(e) = send_auth_notification(&ip.to_string()).await {
                error!("发送通知失败: {}", e);
                NOTIFICATION_CACHE.invalidate(&ip).await;
            }
        } else {
            debug!("发送所冷却中: {}", ip);
        }
        return Ok(());
    }
    debug!("接受授权 IP 连接: {}", ip);
    
    let internal_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, CONFIG.read().unwrap().get_ss_internal_port()));
    match TcpStream::connect(internal_addr).await {
        Ok(mut internal_socket) => {
            match copy_bidirectional(&mut client_socket, &mut internal_socket).await {
                Ok((to_server, to_client)) => {
                    // 传输完成（连接关闭）
                    debug!("连接结束，上传: {} bytes, 下载: {} bytes", to_server, to_client);
                }
                Err(e) => {
                    // 网络中断等常见错误，通常不需要打印 error 级别
                    debug!("转发连接中断: {}", e);
                }
            }
        }
        Err(e) => {
            error!("无法连接内部 SS 服务: {}", e);
        }
    };
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    // TODO 添加服务启动nyft
    // TODO 检查unwarp

    info!("启动ss转发服务");
    tokio::spawn(async {
        if let Err(e) = start_ss_service().await {
            error!("内部 Shadowsocks 服务崩溃: {}", e);
        }
    });

    info!("启动ntfy认证服务");
    info!("请求频道: {}", &CONFIG.read().unwrap().get_ntfy_req_topic());
    info!("响应频道: {}", &CONFIG.read().unwrap().get_ntfy_resp_topic());
    tokio::spawn(async {
        start_ntfy_service().await
    });

    let bind_addr = format!("{}:{}", CONFIG.read().unwrap().get_public_ip(), CONFIG.read().unwrap().get_public_port());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .context("无法绑定公共端口")?;
    info!("对外监听已启动: {}", bind_addr);
    loop {
        let (client_socket, peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(client_socket, peer_addr).await {
                error!("处理客户端连接失败: {}", e);
            }
        });
    }
}

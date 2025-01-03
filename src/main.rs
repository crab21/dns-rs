use core::error;
use dashmap::{DashMap, Map};
use futures::future::{join, join_all};
use futures::TryFutureExt;
use hickory_client::op::{Message, Query};
use hickory_client::rr::domain;
use hickory_client::rr::rdata::NULL;
use hickory_client::rr::{Name, RecordType};
use hickory_client::serialize::binary::{BinDecodable, BinEncodable};
use reqwest::tls::Version;
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use std::alloc::System;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration, Instant};

use serde_yaml;
use std::{fs, string};

use chrono::{NaiveDateTime, TimeZone, Utc};
use once_cell::sync::Lazy;

use std::ptr;

#[derive(Debug, Deserialize, Clone)]
struct Config {
    dohs: Vec<String>,
    port: u16,
    timeout: u64,
    clear_cache_interval: u64,
    ttl_duration: u64,
    enable_clear_expired_cache: bool,
    resolve_skip_domains: Vec<String>,
    enable_cache: bool,
    enable_sniffing: bool,
    map_init_capacity: u64,
    map_init_shard_amount: u64,
    ttl_range_multi: HashMap<u64, u64>,
}
use std::sync::Arc;

async fn create_dashmap(
    config: Config,
) -> Result<Arc<DashMap<String, Arc<DOHResponse>>>, Box<dyn std::error::Error + Send + Sync>> {
    let dashmap: Arc<DashMap<String, Arc<DOHResponse>>> =
        Arc::new(DashMap::with_capacity_and_shard_amount(
            config.map_init_capacity as usize,
            config.map_init_shard_amount as usize,
        ));
    Ok(dashmap)
}

async fn create_client() -> Result<Arc<Client>, Box<dyn std::error::Error + Send + Sync>> {
    let client = ClientBuilder::new()
        .tcp_keepalive(Some(Duration::from_secs(60))) // 设置 TCP 保活时间
        .http2_keep_alive_interval(Some((Duration::from_secs(10)))) // 设置 HTTP/2 保活时间
        .http2_keep_alive_while_idle(true)
        .http2_prior_knowledge() // 启用 HTTP/2 优化
        .https_only(true)
        .http2_adaptive_window(true)
        .pool_max_idle_per_host(900) // 设置每个主机的最大空闲连接数
        .pool_idle_timeout(None) // 设置连接池空闲超时时间
        .use_rustls_tls()
        .tcp_nodelay(true)
        .min_tls_version(Version::TLS_1_2) // 设置最小 TLS 版本
        .max_tls_version(Version::TLS_1_3) // 设置最大 TLS 版本
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONNECTION,
                reqwest::header::HeaderValue::from_static("keep-alive"),
            );
            headers.insert(
                reqwest::header::ACCEPT_ENCODING,
                reqwest::header::HeaderValue::from_static("gzip, deflate, br"),
            ); // 启用 Gzip, Deflate, Brotli 支持

            headers
        })
        // .http3_prior_knowledge()
        .build()?;
    Ok(Arc::new(client))
}

struct DOHRequest {
    domain_names: Vec<String>,
    id: u16,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct DOHResponse {
    pub resp: Vec<u8>,
    pub exipre_time: u64,
    pub ttl: u64,
    pub last_update: u64,
    pub first_update: u64,
}

fn parse_domain_name(query: &[u8]) -> Result<DOHRequest, Box<dyn std::error::Error + Send + Sync>> {
    let message = Message::from_bytes(query)?;
    let questions = message.queries();
    let domain_names = questions.iter().map(|q| q.name().to_string()).collect();
    Ok(DOHRequest {
        domain_names,
        id: message.id(),
    })
}

fn parse_ip_addresses(
    response: &[u8],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let message = Message::from_bytes(response)?;
    let answers = message.answers();
    let ips = answers
        .iter()
        .filter_map(|record| {
            match record
                .data()
                .unwrap_or(&hickory_client::rr::RData::NULL(Default::default()))
            {
                hickory_client::rr::RData::A(ip) => Some(ip.to_string()),
                hickory_client::rr::RData::AAAA(ip) => Some(ip.to_string()),
                _ => None,
            }
        })
        .collect();
    Ok(ips)
}

use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH}; // 导入 Rng trait

fn parse_ip_ttl(
    response: &[u8],
    config: Config,
) -> Result<Arc<DOHResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let message = Message::from_bytes(response)?;
    let answers = message.answers();
    let ttl = answers.iter().map(|record| record.ttl()).min().unwrap_or(0);
    let ips: Vec<String> = answers
        .iter()
        .filter_map(|record| {
            match record
                .data()
                .unwrap_or(&hickory_client::rr::RData::NULL(Default::default()))
            {
                hickory_client::rr::RData::A(ip) => Some(ip.to_string()),
                hickory_client::rr::RData::AAAA(ip) => Some(ip.to_string()),
                _ => None,
            }
        })
        .collect();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut rng = rand::thread_rng(); // 创建随机数生成器
    let random_number: i32 = rng.gen_range(15..=100); // 生成 1 到 100 的随机整数
    let expire_time = now + (ttl as u64) + config.ttl_duration + (random_number as u64);
    // if ips.len() > 0 && ips.get(0).unwrap_or(&String::from("")).contains(":") {
    //     expire_time = expire_time - config.ttl_duration - (random_number as u64);
    // }

    let responseResult = DOHResponse {
        resp: response.to_vec(),
        exipre_time: expire_time,
        ttl: ttl as u64,
        last_update: now,
        first_update: now,
        ..Default::default()
    };
    Ok(Arc::new(responseResult))
}

async fn find_and_update(
    domain: String,
    globalDashMap: Arc<DashMap<String, Arc<DOHResponse>>>,
    client: Arc<Client>,
    doh_urls: Vec<String>,
    requestBody: Vec<u8>,
    config: Config,
) {
    let global_dash_map_clone = Arc::clone(&globalDashMap);
    let client_clone = client.clone();
    let config_clone = config.clone();
    let domain_clone = domain.clone();
    if config_clone.enable_cache == false {
        return;
    }

    tokio::spawn(async move {
        let ttl = global_dash_map_clone
            .get(&domain_clone)
            .map(|v| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                let mut multi_num = v.ttl;
                config.ttl_range_multi.keys().collect::<Vec<&u64>>().sort();
                for (k, vv) in config.ttl_range_multi.iter() {
                    if *k > v.ttl {
                        multi_num = multi_num * (*vv);
                        break;
                    }
                    continue;
                }
                if v.ttl > 0 && now <= v.ttl + v.last_update + multi_num {
                    return 0;
                }
                if (now - v.last_update) < 60 {
                    return 0;
                }
                println!(
                    "check domain {:?} need to update, ttl:{:?}, last_update:{:?}",
                    domain_clone, v.exipre_time, v.last_update
                );
                v.ttl
            })
            .unwrap_or_else(|| 0);
        if ttl == 0 {
            return;
        }

        if let Ok(rr) =
            forward_to_fastest_doh(client_clone, domain_clone, requestBody, doh_urls, config).await
        {
            let rcopy = rr.clone();
            match parse_ip_ttl(rcopy.as_slice(), config_clone) {
                Ok(resp) => {
                    println!(
                        "*******Caching response for domain: {:?}*******",
                        domain.clone()
                    );
                    global_dash_map_clone.insert(domain, resp);
                }
                Err(e) => {
                    eprintln!("Failed to parse TTL: {}", e);
                }
            }
        };
        println!("globalDashMap len is: {:?}", globalDashMap.len());
    });
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 读取 YAML 文件
    let yaml_content = fs::read_to_string("config.yaml")?;

    // 解析 YAML 内容为 Config 结构体
    let config: Config = serde_yaml::from_str(&yaml_content)?;

    // 打印解析后的结果
    println!("Config: {:?}", config);
    let globalDashMap = create_dashmap(config.clone()).await?;

    // Listen on UDP port 53
    let address = format!("{}{}", "0.0.0.0:", config.port);
    let sc = UdpSocket::bind(address.clone()).await?;
    let std_sock = sc.into_std()?;
    std_sock.set_nonblocking(true);
    std_sock.set_write_timeout(Some(Duration::from_secs(15)));

    let sock = UdpSocket::from_std(std_sock)?;

    let socket = Arc::new(sock);
    println!("Listening on ...{:?}", address);
    let client = create_client().await?;

    let mut buf = [0u8; 512];

    let global_dash_map_clone = Arc::clone(&globalDashMap);
    tokio::spawn(async move {
        if config.enable_cache == false {
            return;
        }

        let mut interval = interval(Duration::from_secs(config.clear_cache_interval));
        loop {
            interval.tick().await;
            global_dash_map_clone.clear(); // 清空 map
            println!("Map cleared!");
        }
    });

    loop {
        // Receive data
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok((len, src)) => (len, src),
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                continue;
            }
        };
        let client_clone = client.clone();
        let config_clone = config.clone();
        let buf_clone = buf.clone();
        let src_clone = src.clone();
        let socket_clone = Arc::clone(&socket);
        if config.enable_cache {
            let global_dash_map_clone = Arc::clone(&globalDashMap);
            let _ = tokio::spawn(async move {
                if let Err(e) = recv_and_do_resolve(
                    global_dash_map_clone,
                    socket_clone,
                    client_clone,
                    config_clone,
                    buf_clone,
                    len,
                    src_clone,
                )
                .await
                {
                    eprintln!("Error in recv_and_do_resolve: {:?}", e);
                }
            });
        } else {
            let _ = tokio::spawn(async move {
                if let Err(e) = recv_and_do_resolve(
                    Default::default(),
                    socket_clone,
                    client_clone,
                    config_clone,
                    buf_clone,
                    len,
                    src_clone,
                )
                .await
                {
                    eprintln!("Error in recv_and_do_resolve: {:?}", e);
                }
            });
        }
    }
}

async fn recv_and_do_resolve(
    globalDashMap: Arc<DashMap<String, Arc<DOHResponse>>>,
    socket: Arc<UdpSocket>,
    client: Arc<Client>,
    config: Config,
    buf: [u8; 512],
    len: usize,
    src: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 解析并打印 DNS 请求的域名
    let mut domainName = String::from("");
    if config.enable_cache {
        if let Ok(dohRequest) = parse_domain_name(&buf[..len]) {
            let domain_names = dohRequest.domain_names;
            println!("Received query for domains: {:?}", domain_names);
            let cloneDomain = domain_names[0].clone();
            let v = globalDashMap.get(&cloneDomain);
            let mut ttlTmp: u64 = 0;
            let value = v
            .map(|v| {
                // 转换为 UTC 时间
                let datetime = Utc.timestamp_opt(v.exipre_time as i64, 0).unwrap();
                let datetime_shanghai = datetime.with_timezone(&chrono_tz::Asia::Shanghai);
                // 格式化为字符串
                let formatted = datetime_shanghai.format("%Y-%m-%d %H:%M:%S").to_string();
                ttlTmp = v.ttl;
                println!(
                    "v.expire_time: {:?}, format time: {:?}, ttl: {:?}",
                    v.exipre_time, formatted, ttlTmp
                );
                if config.enable_clear_expired_cache {
                    if v.exipre_time
                        < SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_secs()
                    {
                        println!(
                            "Cache expired for domain: {:?}, v.expire_time: {:?}, format time: {:?}, ttl: {:?}",
                            cloneDomain, v.exipre_time, formatted, ttlTmp
                        );
                        return vec![];
                    }
                    v.resp.clone()
                } else {
                    v.resp.clone()
                }
            })
            .unwrap_or_else(|| vec![]);
            domainName = domain_names[0].clone(); // 正确更新 domainName
            if value.len() > 0 {
                println!();
                let mut message = Message::from_bytes(&value)?;
                message.set_id(dohRequest.id);
                // 解析并打印 DNS 响应中的 IP 地址
                if let Ok(ips) = parse_ip_addresses(&value) {
                    if ips.len() > 0 {
                        println!(
                            "Cache hit for domain: {:?} ,Response contains IPs: {:?}, ttl: {:?}",
                            cloneDomain, ips, ttlTmp
                        );
                        let sendRespose = socket.send_to(&message.to_vec().unwrap(), src).await;

                        match sendRespose {
                            Ok(_) => {
                                if config.enable_sniffing {
                                    find_and_update(
                                        cloneDomain,
                                        globalDashMap,
                                        client,
                                        config.dohs.clone(),
                                        buf[..len].to_vec(),
                                        config.clone(),
                                    )
                                    .await;
                                }

                                return Ok(());
                            }
                            Err(e) => {
                                eprintln!("Failed to send response: {}", e);
                            }
                        }
                    } else {
                        eprintln!("dns len is zero,,,,Failed to parse DNS response, re-resolve dns domain {:?}", cloneDomain);
                    }
                } else {
                    eprintln!(
                        "Failed to parse DNS response,re-resolve dns domain {:?}",
                        cloneDomain
                    );
                }
            }
        } else {
            eprintln!("Failed to parse DNS query to get domain name");
        }
    } else {
        if let Ok(dohRequest) = parse_domain_name(&buf[..len]) {
            let domain_names = dohRequest.domain_names;
            domainName = domain_names[0].clone(); // 正确更新 domainName
        }
    }

    println!("Received DNS query from {}", src);
    // Forward to DoH servers and get the fastest response
    match forward_to_fastest_doh(
        client,
        domainName.clone(),
        buf[..len].to_vec(),
        config.dohs.clone(),
        config.clone(),
    )
    .await
    {
        Ok(response) => {
            // Forward DoH response back to the client
            if let Err(e) = socket.send_to(&response, src).await {
                eprintln!("Failed to send response: {}", e);
                return Err(e.into());
            }
            // 缓存响应
            let cc = config.clone();
            let rcopy = response.clone();
            match parse_ip_ttl(rcopy.as_slice(), config) {
                Ok(resp) => {
                    if cc.enable_cache {
                        println!(
                            "Caching response for domain: {:?}, IPs: {:?}",
                            domainName.clone(),
                            parse_ip_addresses(&resp.resp).unwrap_or_default()
                        );
                        globalDashMap.insert(domainName, resp);
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Failed to parse TTL: {}", e);
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            eprintln!("DoH request failed: {}", e);
            Err(e.into())
        }
    }
}
/// Forward DNS query to the fastest DoH server from a list of servers
async fn forward_to_fastest_doh(
    client: Arc<Client>,
    domain: String,
    requestBody: Vec<u8>,
    doh_urls: Vec<String>,
    config: Config,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (tx, mut rx) = mpsc::channel::<Option<(Duration, Vec<u8>, String)>>(1); // 通道的缓冲区为

    for url in doh_urls {
        let client_clone = client.clone();
        let domainName = domain.clone();
        let query = requestBody.to_vec();
        let tx = tx.clone(); // 克隆发送者，确保每个任务都有一个发送通道
        let urlClone = url.clone(); // 克隆 URL，确保每个任务都有一个 URL 副本
        let resolve_domain = config.resolve_skip_domains.clone();
        tokio::spawn(async move {
            let start_time = Instant::now();
            let mut queryDns: Message = Message::from_bytes(&query).unwrap();
            let qtype: Vec<RecordType> =
                queryDns.queries().iter().map(|q| q.query_type()).collect();

            let domain_names: Vec<String> = queryDns
                .queries()
                .iter()
                .map(|q| q.name().to_string())
                .collect();
            let domain_name = domain_names.get(0).unwrap_or(&String::from("")).clone();
            println!(
                "Skip resolve domain: {:?}, query_type: {:?}",
                domain_name,
                qtype.get(0).unwrap_or(&RecordType::A).to_string()
            );
            let response = timeout(
                Duration::from_secs(5),
                client_clone
                    .post(url)
                    .header("Content-Type", "application/dns-message")
                    .body(queryDns.to_vec().unwrap())
                    .timeout(Duration::from_millis(config.timeout))
                    .send(),
            )
            .await;

            match response {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    let elapsed = start_time.elapsed();
                    let response_bytes = resp.bytes().await.unwrap_or_default();
                    tx.send(Some((elapsed, response_bytes.to_vec(), urlClone)))
                        .await
                        .unwrap_or_else(|_| ()); // 发送到通道
                }

                Ok(Ok(resp)) if resp.status().is_success() == false => {
                    println!(
                        "[NOT-SUCCESS] domain: {:?}, Failed to send request to {}",
                        domainName, urlClone
                    );
                    eprintln!(
                        "Failed to send request to {}",
                        resp.text().await.unwrap_or_default()
                    );
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                }

                Ok(Err(e)) => {
                    // 处理 reqwest 错误
                    eprintln!("domain: {:?},Failed to send request: {}", domainName, e);
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                }
                Err(e) => {
                    // 处理超时错误
                    eprintln!("domain: {:?}, Request timed out: {}", domainName, e);
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                }
                _ => {
                    println!(
                        "domain: {:?},Failed to send request to {}",
                        domainName, urlClone
                    );
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                    // 发送到通道
                }
            }
        });
    }

    // 等待第一个完成的结果
    if let Some((elapsed, response, url)) = rx.recv().await.flatten() {
        println!(
            "Received domain: {:?} response from {} in {:?}",
            domain, url, elapsed
        );
        // 解析并打印 DNS 响应中的 IP 地址
        if let Ok(ips) = parse_ip_addresses(&response) {
            println!(
                "Response domain: {:?} contains IPs: {:?}, from DOH: [{}]",
                domain, ips, url
            );
        } else {
            eprintln!("Failed to parse DNS response");
        }
        rx.close();

        // 返回第一个成功的响应
        return Ok(response.to_vec());
    }

    // 如果没有收到任何成功响应，返回错误
    Err("No successful DoH response received".into())
}

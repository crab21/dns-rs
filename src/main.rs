use core::error;
use dashmap::{DashMap, Map};
use futures::future::{join, join_all};
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use std::borrow::{Borrow, BorrowMut};
use std::error::Error;
use std::io::Read;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration, Instant};
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::domain;
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use serde_yaml;
use std::{fs, string};

use chrono::{NaiveDateTime, TimeZone, Utc};
use once_cell::sync::Lazy;

#[derive(Debug, Deserialize, Clone)]
struct Config {
    dohs: Vec<String>,
    port: u16,
    timeout: u64,
    clear_cache_interval: u64,
}
use std::sync::Arc;

async fn create_dashmap(
) -> Result<Arc<DashMap<String, DOHResponse>>, Box<dyn std::error::Error + Send + Sync>> {
    let dashmap = Arc::new(DashMap::new());
    Ok(dashmap)
}

async fn create_client() -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    let client = ClientBuilder::new()
        .http2_prior_knowledge() // 启用 HTTP/2 优化
        .pool_max_idle_per_host(900) // 设置每个主机的最大空闲连接数
        .pool_idle_timeout(Some(Duration::from_secs(90))) // 设置连接池空闲超时时间
        .timeout(Duration::from_secs(10)) // 设置请求超时时间
        .build()?;
    Ok(client)
}

struct DOHRequest {
    domain_names: Vec<String>,
    id: u16,
}

struct DOHResponse {
    pub resp: Vec<u8>,
    pub exipre_time: u64,
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
        .filter_map(|record| match record.rdata() {
            trust_dns_proto::rr::RData::A(ip) => Some(ip.to_string()),
            trust_dns_proto::rr::RData::AAAA(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect();
    Ok(ips)
}

use std::time::{SystemTime, UNIX_EPOCH};

fn parse_ip_ttl(response: &[u8]) -> Result<DOHResponse, Box<dyn std::error::Error + Send + Sync>> {
    let message = Message::from_bytes(response)?;
    let answers = message.answers();
    let ttl = answers.iter().map(|record| record.ttl()).min().unwrap_or(0);
    let resp = DOHResponse {
        resp: response.to_vec(),
        exipre_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            + ttl as u64,
    };
    Ok(resp)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let globalDashMap = create_dashmap().await?;

    // 读取 YAML 文件
    let yaml_content = fs::read_to_string("config.yaml")?;

    // 解析 YAML 内容为 Config 结构体
    let config: Config = serde_yaml::from_str(&yaml_content)?;

    // 打印解析后的结果
    println!("Config: {:?}", config);

    // Listen on UDP port 53
    let address = format!("{}{}", "0.0.0.0:", config.port);
    let socket = Arc::new(UdpSocket::bind(address.clone()).await?);
    println!("Listening on ...{:?}", address);
    let client = create_client().await?;

    let mut buf = [0u8; 512];

    let global_dash_map_clone = Arc::clone(&globalDashMap);
    tokio::spawn(async move {
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
        let global_dash_map_clone = Arc::clone(&globalDashMap);
        let client_clone = client.clone();
        let config_clone = config.clone();
        let buf_clone = buf.clone();
        let src_clone = src.clone();
        let socket_clone = Arc::clone(&socket);
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
    }
}

async fn recv_and_do_resolve(
    globalDashMap: Arc<DashMap<String, DOHResponse>>,
    socket: Arc<UdpSocket>,
    client: Client,
    config: Config,
    buf: [u8; 512],
    len: usize,
    src: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 解析并打印 DNS 请求的域名
    let mut domainName = String::from("");
    if let Ok(dohRequest) = parse_domain_name(&buf[..len]) {
        let domain_names = dohRequest.domain_names;
        println!("Received query for domains: {:?}", domain_names);
        let cloneDomain = domain_names[0].clone();
        let value = globalDashMap
            .get(&cloneDomain)
            .map(|v| {
                // 转换为 UTC 时间
                let datetime = Utc.timestamp_opt(v.exipre_time as i64, 0).unwrap();

                // 格式化为字符串
                let formatted = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                println!(
                    "v.expire_time: {:?}, format time: {:?}",
                    v.exipre_time, formatted
                );
                if v.exipre_time
                    > SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs()
                {
                    println!(
                        "Cache hit for domain: {:?} ,Response contains IPs: {:?}, from DOH: []",
                        cloneDomain,
                        parse_ip_addresses(&v.resp).unwrap()
                    );
                    v.resp.clone()
                } else {
                    println!("Cache expired for domain: {:?}", cloneDomain);
                    vec![]
                }
            })
            .unwrap_or_else(|| vec![]);
        println!("globalDashMap len is: {:?}", globalDashMap.len());
        domainName = domain_names[0].clone(); // 正确更新 domainName
        if value.len() > 0 {
            println!();
            let mut message = Message::from_bytes(&value)?;
            message.set_id(dohRequest.id);
            // 解析并打印 DNS 响应中的 IP 地址
            if let Ok(ips) = parse_ip_addresses(&value) {
                if ips.len() > 0 {
                    println!(
                        "Cache hit for domain: {:?} ,Response contains IPs: {:?}, from DOH: []",
                        cloneDomain, ips
                    );
                    let sendRespose = socket.send_to(&message.to_vec().unwrap(), src).await;
                    match sendRespose {
                        Ok(_) => {
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Failed to send response: {}", e);
                        }
                    }
                } else {
                    globalDashMap.remove(&cloneDomain);
                    eprintln!("dns len is zero,,,,Failed to parse DNS response, re-resolve dns domain {:?}", cloneDomain);
                }
            } else {
                globalDashMap.remove(&cloneDomain);
                eprintln!(
                    "Failed to parse DNS response,re-resolve dns domain {:?}",
                    cloneDomain
                );
            }
        } else {
            globalDashMap.remove(&cloneDomain);
        }
    } else {
        eprintln!("Failed to parse DNS query to get domain name");
    }

    println!("Received DNS query from {}", src);
    // Forward to DoH servers and get the fastest response
    match forward_to_fastest_doh(
        &client,
        domainName.clone(),
        buf[..len].to_vec(),
        config.dohs.clone(),
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
            println!("Caching response for domain: {:?}", domainName.clone());
            match parse_ip_ttl(response.clone().as_slice()) {
                Ok(resp) => {
                    globalDashMap.insert(domainName, resp);
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
    client: &Client,
    domainName: String,
    requestBody: Vec<u8>,
    doh_urls: Vec<String>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let (tx, mut rx) = mpsc::channel::<Option<(Duration, Vec<u8>, String)>>(1); // 通道的缓冲区为 1
                                                                                // Spawn asynchronous tasks for each DoH server
    for url in doh_urls {
        let client = client.clone();
        let query = requestBody.to_vec();
        let tx = tx.clone(); // 克隆发送者，确保每个任务都有一个发送通道
        let urlClone = url.clone(); // 克隆 URL，确保每个任务都有一个 URL 副本

        tokio::spawn(async move {
            let start_time = Instant::now();
            let response = timeout(
                Duration::from_secs(5),
                client
                    .post(url)
                    .header("Content-Type", "application/dns-message")
                    .body(query)
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
                    println!("[NOT-SUCCESS] Failed to send request to {}", urlClone);
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
                    eprintln!("Failed to send request: {}", e);
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                }
                Err(e) => {
                    // 处理超时错误
                    eprintln!("Request timed out: {}", e);
                    tx.send(None)
                        .await
                        .unwrap_or_else(|err| (println!("{:?}", err)));
                }
                _ => {
                    println!("Failed to send request to {}", urlClone);
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
        println!("Received response from {} in {:?}", url, elapsed);
        // 解析并打印 DNS 响应中的 IP 地址
        if let Ok(ips) = parse_ip_addresses(&response) {
            println!("Response contains IPs: {:?}, from DOH: [{}]", ips, url);
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

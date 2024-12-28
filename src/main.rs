use core::error;
use dashmap::DashMap;
use futures::future::{join, join_all};
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use std::borrow::{Borrow, BorrowMut};
use std::error::Error;
use std::io::Read;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration, Instant};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::domain;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use serde_yaml;
use std::{fs, string};

use once_cell::sync::Lazy;

#[derive(Debug, Deserialize)]
struct Config {
    dohs: Vec<String>,
    port: u16,
    timeout: u64,
    clear_cache_interval: u64,
}
use std::sync::Arc;

async fn create_dashmap() -> Result<Arc<DashMap<String, Vec<u8>>>, Box<dyn std::error::Error>> {
    let dashmap = Arc::new(DashMap::new());
    Ok(dashmap)
}

async fn create_client() -> Result<Client, Box<dyn std::error::Error>> {
    let client = ClientBuilder::new()
        .http2_prior_knowledge() // 启用 HTTP/2 优化
        .pool_idle_timeout(Some(Duration::from_secs(90))) // 设置连接池空闲超时时间
        .timeout(Duration::from_secs(10)) // 设置请求超时时间
        .build()?;
    Ok(client)
}

struct DOHRequest {
    domain_names: Vec<String>,
    id: u16,
}

fn parse_domain_name(query: &[u8]) -> Result<DOHRequest, Box<dyn std::error::Error>> {
    let message = Message::from_bytes(query)?;
    let questions = message.queries();
    let domain_names = questions.iter().map(|q| q.name().to_string()).collect();
    Ok(DOHRequest {
        domain_names,
        id: message.id(),
    })
}

fn parse_ip_addresses(response: &[u8]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let globalDashMap = create_dashmap().await?;

    // 读取 YAML 文件
    let yaml_content = fs::read_to_string("config.yaml")?;

    // 解析 YAML 内容为 Config 结构体
    let config: Config = serde_yaml::from_str(&yaml_content)?;

    // 打印解析后的结果
    println!("Config: {:?}", config);

    // Listen on UDP port 53
    let address = format!("{}{}", "0.0.0.0:", config.port);
    let socket = UdpSocket::bind(address.clone()).await?;
    println!("Listening on ...{:?}", address);
    let client = create_client().await?;

    let mut buf = [0u8; 512];

    let globalDashMap_clone = globalDashMap.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(config.clear_cache_interval));
        loop {
            interval.tick().await;
            globalDashMap_clone.clear(); // 清空 map
            println!("Map cleared!");
        }
    });

    loop {
        let mut domainName = String::from("");
        // Receive data
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok((len, src)) => (len, src),
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                continue;
            }
        };

        // 解析并打印 DNS 请求的域名

        if let Ok(dohRequest) = parse_domain_name(&buf[..len]) {
            let domain_names = dohRequest.domain_names;
            println!("Received query for domains: {:?}", domain_names);
            let cloneDomain = domain_names[0].clone();
            let globalDashMap = globalDashMap.clone();
            let value = globalDashMap
                .get(&cloneDomain)
                .map(|v| v.clone())
                .unwrap_or_else(|| vec![]);
            domainName = domain_names[0].clone(); // 正确更新 domainName
            if value.len() > 0 {
                println!("Cache hit for domain: {:?}", cloneDomain);
                let mut message = Message::from_bytes(&value)?;
                message.set_id(dohRequest.id);
                // 解析并打印 DNS 响应中的 IP 地址
                if let Ok(ips) = parse_ip_addresses(&value) {
                    if ips.len() > 0 {
                        println!("Response contains IPs: {:?}, from DOH: []", ips);
                        if let Err(e) = socket.send_to(&message.to_vec().unwrap(), src).await {
                            eprintln!("Failed to send response: {}", e);
                            continue;
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
            }
        } else {
            eprintln!("Failed to parse DNS query to get domain name");
        }

        println!("Received DNS query from {}", src);
        // Forward to DoH servers and get the fastest response
        match forward_to_fastest_doh(&client, &buf[..len], config.dohs.clone()).await {
            Ok(response) => {
                // Forward DoH response back to the client
                if let Err(e) = socket.send_to(&response, src).await {
                    eprintln!("Failed to send response: {}", e);
                }
                // 缓存响应
                println!("Caching response for domain: {:?}", domainName);
                globalDashMap.insert(domainName, response.clone());
            }
            Err(e) => eprintln!("DoH request failed: {}", e),
        }
    }
}

/// Forward DNS query to the fastest DoH server from a list of servers
async fn forward_to_fastest_doh(
    client: &Client,
    query: &[u8],
    doh_urls: Vec<String>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let (tx, mut rx) = mpsc::channel::<Option<(Duration, Vec<u8>, String)>>(1); // 通道的缓冲区为 1

    // Spawn asynchronous tasks for each DoH server
    for url in doh_urls {
        let client = client.clone();
        let query = query.to_vec();
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

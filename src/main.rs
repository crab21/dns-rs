use core::error;
use futures::future::{join, join_all};
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use std::error::Error;
use std::io::Read;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration, Instant};
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

#[derive(Deserialize, Debug)]
struct Answer {
    name: String,
    data: String,
}

#[derive(Deserialize, Debug)]
struct DnsResponse {
    Answer: Vec<Answer>,
}

use serde_yaml;
use std::{fs, string};

#[derive(Debug, Deserialize)]
struct Config {
    dohs: Vec<String>,
    port: u16,
    timeout: u64,
}

async fn create_client() -> Result<Client, Box<dyn std::error::Error>> {
    let client = ClientBuilder::new()
        .http2_prior_knowledge() // 启用 HTTP/2 优化
        .pool_idle_timeout(Some(Duration::from_secs(90))) // 设置连接池空闲超时时间
        .timeout(Duration::from_secs(10)) // 设置请求超时时间
        .build()?;
    Ok(client)
}

fn parse_domain_name(query: &[u8]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let message = Message::from_bytes(query)?;
    let questions = message.queries();
    let domain_names = questions.iter().map(|q| q.name().to_string()).collect();
    Ok(domain_names)
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
    std::env::set_var("RING_NO_ASM", "1");

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
    loop {
        // Receive data
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok((len, src)) => (len, src),
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                continue;
            }
        };

        // 解析并打印 DNS 请求的域名
        if let Ok(domain_names) = parse_domain_name(&buf[..len]) {
            println!("Received query for domains: {:?}", domain_names);
        } else {
            eprintln!("Failed to parse DNS query");
        }

        println!("Received DNS query from {}", src);
        // Forward to DoH servers and get the fastest response
        match forward_to_fastest_doh(&client, &buf[..len], config.dohs.clone()).await {
            Ok(response) => {
                // Forward DoH response back to the client
                if let Err(e) = socket.send_to(&response, src).await {
                    eprintln!("Failed to send response: {}", e);
                }
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

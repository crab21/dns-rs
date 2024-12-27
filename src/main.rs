use futures::future::join_all;
use reqwest::{Client,ClientBuilder};
use serde::Deserialize;
use std::error::Error;
use std::io::Read;
use tokio::net::UdpSocket;
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
    let address = format!("{}{}","0.0.0.0:",config.port);
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
        println!("Received DNS query from {}", src);
        // Forward to DoH servers and get the fastest response
        match forward_to_fastest_doh(&client,&buf[..len], config.dohs.clone()).await {
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
async fn forward_to_fastest_doh(client: &Client,query: &[u8],doh_urls: Vec<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    let client = Client::new();
    let mut futures = Vec::new();

    // Spawn asynchronous tasks for each DoH server
    for url in doh_urls {
        let client = client.clone();
        let query = query.to_vec();
        let future = async move {
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
                    Some((elapsed, response_bytes.to_vec()))
                }
                _ => None,
            }
        };
        futures.push(future);
    }

    // Execute all requests concurrently
    let results = join_all(futures).await;

    // Filter and find the fastest response
    let mut fastest_response: Option<(Duration, Vec<u8>)> = None;
    for result in results {
        if let Some((elapsed, response)) = result {
            println!("DoH response received in {:?}", elapsed);
            if fastest_response.is_none() || elapsed < fastest_response.as_ref().unwrap().0 {
                fastest_response = Some((elapsed, response));
            }
            break;
        }
    }

    // Return the fastest response or an error if none succeeded
    fastest_response
        .map(|(_, response)| response)
        .ok_or_else(|| "No successful DoH response received".into())
}

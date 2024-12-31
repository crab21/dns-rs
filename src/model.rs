use serde::{Deserialize, Serialize};
#[derive(Serialize)]
pub struct DnsQuery {
    #[serde(rename = "type")]
    pub query_type: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct DnsAnswer {
  pub name: String,
    #[serde(rename = "type")]
    pub answer_type: u16,
    pub TTL: u32,
    pub data: String,
}

#[derive(Deserialize)]
pub struct DnsResponse {
    pub Status: u8,
    pub Answer: Option<Vec<DnsAnswer>>,
}
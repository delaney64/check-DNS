use anyhow::Result;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::lookup::TxtLookup;
use trust_dns_resolver::proto::rr::rdata::TXT;

use crate::errors::DnsError;

// Helper function to convert TXT record data to a string
pub fn txt_to_string(txt: &TXT) -> String {
    txt.txt_data()
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect::<Vec<_>>()
        .join("")
}


/// Parse SPF record and extract specific mechanisms
fn parse_spf_record(spf_record: &str) -> Vec<String> {
    let mut mechanisms = Vec::new();

    // Split the record into parts by whitespace
    for part in spf_record.split_whitespace() {
        // Only collect parts that start with include:, ip4:, or ip6:
        if part.starts_with("include:") || part.starts_with("ip4:") || part.starts_with("ip6:") {
            mechanisms.push(part.to_string());
        }
    }

    mechanisms
}
// The main check_spf function will go here
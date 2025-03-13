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
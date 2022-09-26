use std::net::{AddrParseError, SocketAddr};

pub fn parse_ip(ip: &String, port: u16) -> Result<SocketAddr, AddrParseError> {
    let chars = ip.chars().collect::<Vec<char>>();

    // Is IPv6
    if chars.contains(&':') {
        return format!("[{}]:{}", ip, port).parse::<SocketAddr>();
    }

    // Is IPv4
    return format!("{}:{}", ip, port).parse::<SocketAddr>();
}

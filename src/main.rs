extern crate getopts;
extern crate nom;

use getopts::Options;
use nom::number::streaming::be_u16;
use nom::number::streaming::be_u8;
use nom::*;
use std::env;
use std::io::prelude::*;
use std::io::Result;
use std::io::*;
use std::mem::replace;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, Shutdown};
use std::time::Duration;
use std::thread;

enum RequestAddressType {
    IPv4 = 0x000001,
    DomainName = 0x000003,
    IPv6 = 0x000004,
    InvalidAddress,
}
impl From<u8> for RequestAddressType {
    fn from(value: u8) -> Self {
        match value {
            1 => RequestAddressType::IPv4,
            2 => RequestAddressType::DomainName,
            3 => RequestAddressType::IPv6,
            _ => RequestAddressType::InvalidAddress,
        }
    }
}

struct SocksConnection {
    dst_socket_addr: SocketAddr,
    server_socket_addr: SocketAddr,
    client_stream: TcpStream,
}
fn get_ipv4_address(buffer: &[u8]) -> std::result::Result<SocketAddr, String> {
    named!(
        parse_ipv4<SocketAddr>,
        do_parse!(
            a: be_u8
                >> b: be_u8
                >> c: be_u8
                >> d: be_u8
                >> port: be_u16
                >> (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
        )
    );
    if let Ok((_, sock_addr)) = parse_ipv4(&buffer) {
        return Ok(sock_addr);
    } else {
        return Err(format!("Can't parse ipv4 address : {:?}", buffer));
    }
}

fn get_domain_name(buffer: &[u8]) -> std::result::Result<SocketAddr, String> {
    named!(
        parse_fqdn<String>,
        do_parse!(
            fqdn_len: be_u8
                >> fqdn: take!(fqdn_len)
                >> port: take!(2)
                >> (format!(
                    "{}:{}",
                    String::from_utf8_lossy(fqdn),
                    String::from_utf8_lossy(port)
                ))
        )
    );
    if let Ok((_, socket_str)) = parse_fqdn(&buffer) {
        if let Ok(mut sock_iter) = socket_str.to_socket_addrs() {
            if let Some(sock_addr) = sock_iter.next() {
                return Ok(sock_addr);
            }
        }
    }
    return Err(format!("Couldn't parse fqdn socket address: {:x?}", buffer));
}

fn get_ipv6_address(buffer: &[u8]) -> std::result::Result<SocketAddr, String> {
    named!(
        parse_ipv6<SocketAddr>,
        do_parse!(
            a: be_u16
                >> b: be_u16
                >> c: be_u16
                >> d: be_u16
                >> e: be_u16
                >> f: be_u16
                >> g: be_u16
                >> h: be_u16
                >> port: be_u16
                >> (SocketAddr::new(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)), port))
        )
    );
    let ip_addr_res = parse_ipv6(&buffer);
    if let Ok((_, sock_addr)) = ip_addr_res {
        return Ok(sock_addr);
    } else {
        return Err(format!("Couldn't parse socket addr: {:?}", ip_addr_res));
    }
}

impl SocksConnection {
    fn new(client_stream: TcpStream, server_socket_addr: SocketAddr) -> Self {
        SocksConnection {
            client_stream,
            server_socket_addr,
            dst_socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0])), 8080),
        }
    }
    fn process_client_request(&mut self) -> std::result::Result<(), String> {
        /*
          The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
         */
        println!("Processing client's request");
        let mut buffer: [u8; 512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        let socks_version = buffer[0];
        let command = buffer[1];
        let address_type = RequestAddressType::from(buffer[3]);
        self.dst_socket_addr = match address_type {
            RequestAddressType::IPv4 => get_ipv4_address(&buffer[4..])?,
            RequestAddressType::DomainName => get_domain_name(&buffer[4..])?,
            RequestAddressType::IPv6 => get_ipv6_address(&buffer[4..])?,
            RequestAddressType::InvalidAddress => {
                return Err(String::from("Invalid address"));
            }
        };

        println!("dst_socket_addr : {}", self.dst_socket_addr);
        //TODO: add support for bind and udpassociate commands
        let mut server_response: [u8; 512] = [0; 512];
        server_response[0] = socks_version;
        server_response[1] = 0;
        server_response[2] = 0;
        server_response[3] = address_type as u8;
        let mut local_addr_octets: Vec<u8> = match self.server_socket_addr.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let local_addr_port = self.server_socket_addr.port();
        local_addr_octets.push((local_addr_port >> 8) as u8);
        local_addr_octets.push(local_addr_port as u8);
        server_response[4..4 + local_addr_octets.len()]
            .clone_from_slice(local_addr_octets.as_slice());

        self.client_stream
            .write(&server_response[..4 + local_addr_octets.len()])
            .expect("Couldn't write to client's stream while processing request");
        self.client_stream.flush().expect("Couldn't flush stream");

        Ok(())
    }

    fn authenticate_client(&mut self) -> std::result::Result<(), String> {
        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+

         */
        println!("Authenticating client");
        let mut buffer: [u8; 512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        let socks_version = buffer[0];
        if socks_version != 5 {
            return Err(format!(
                "Expected socks version 5, given: {}",
                socks_version
            ));
        }
        let number_of_methods = buffer[1];
        if number_of_methods == 0 {
            return Err(String::from("No methods specified"));
        }
        let mut methods: Vec<AuthenticationMethods> = Vec::new();
        for method_byte in 0..number_of_methods {
            methods.push(AuthenticationMethods::from(
                buffer[2 + method_byte as usize],
            ));
        }
        self.client_stream
            .write(&[
                socks_version,
                std::mem::replace(
                    methods.first_mut().unwrap(),
                    AuthenticationMethods::InvalidMethod,
                ) as u8,
            ])
            .expect("Couldn't write to stream while authenticating");
        self.client_stream.flush().expect("Couldn't flush stream");
        println!("Authenticated succesfully");
        Ok(())
    }

    fn perform_request(&mut self) -> std::result::Result<(), String> {
        let mut buffer: Vec<u8> = vec![0;8192];
        let mut bytes_read = 0;
        let mut bytes_written = 0;
        let mut conn: TcpStream = match TcpStream::connect(self.dst_socket_addr) {
            Ok(stream) => {
                println!("Connected to {}", self.dst_socket_addr);
                stream
            }
            Err(message) => {
                return Err(format!(
                    "Coudln't connect to destination address. : {}",
                    message
                ));
            }
        };
        
        let mut remote_to_proxy = conn.try_clone().unwrap();
        let mut proxy_to_remote = conn.try_clone().unwrap();
        let mut client_to_proxy = self.client_stream.try_clone().unwrap();
        let mut proxy_to_client = self.client_stream.try_clone().unwrap();


        thread::spawn(move || {
            copy(&mut remote_to_proxy, &mut proxy_to_client).unwrap();
            remote_to_proxy.shutdown(Shutdown::Read).unwrap();
            proxy_to_client.shutdown(Shutdown::Write).unwrap();
        });

        thread::spawn(move || {
            copy(&mut client_to_proxy, &mut proxy_to_remote).unwrap();
            client_to_proxy.shutdown(Shutdown::Read).unwrap();
            proxy_to_remote.shutdown(Shutdown::Write).unwrap();
        });
        return Ok(());
    }

    fn handle_connection(&mut self) -> std::result::Result<(), String> {
        self.authenticate_client()?;
        self.process_client_request()?;
        self.perform_request()?;
        Ok(())
    }

    fn handle_stream(&mut self) -> std::result::Result<(), String> {
        self.handle_connection()?;
        Ok(())
    }
}

struct Server {
    listener: TcpListener,
}

impl Server {
    fn new(full_address: String) -> std::result::Result<Self, String> {
        if let Ok(listener) = TcpListener::bind(&full_address) {
            return Ok(Server { listener });
        }
        Err(format!("Couldn't bind to address {}", full_address))
    }

    fn server_loop(&mut self) -> Result<()> {
        for stream in self.listener.incoming() {
            println!("Attempting to handle connection");
            let mut socks_conn =
                SocksConnection::new(stream.unwrap(), self.listener.local_addr().unwrap());

            match socks_conn.handle_stream() {
                Ok(()) => {}
                Err(message) => println!("{}", message),
            }

            println!("connection closed");
        }
        Ok(())
    }
}

enum RequestCommandMode {
    Noop,
    Connect,
    Bind,
    UdpAssociate,
    InvalidMode,
}
impl From<u8> for RequestCommandMode {
    fn from(x: u8) -> Self {
        match x {
            0 => RequestCommandMode::Noop,
            1 => RequestCommandMode::Connect,
            2 => RequestCommandMode::Bind,
            3 => RequestCommandMode::UdpAssociate,
            _ => RequestCommandMode::InvalidMode,
        }
    }
}

enum AuthenticationMethods {
    NoAuth,
    GSSAPI,
    UsernamePassword,
    InvalidMethod,
}

impl From<u8> for AuthenticationMethods {
    fn from(value: u8) -> Self {
        match value {
            0 => AuthenticationMethods::NoAuth,
            1 => AuthenticationMethods::GSSAPI,
            2 => AuthenticationMethods::UsernamePassword,
            _ => AuthenticationMethods::InvalidMethod,
        }
    }
}

enum RequestAddress {
    IPv4(i32),
    DomainName(String),
    IPv6(i64),
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn send_version_mismatch() {}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() == 1 {
        println!("Usage: kneesocks --address <127.0.0.1> --port <1111>.");
        ::std::process::exit(1);
    }

    let mut opts = Options::new();
    opts.reqopt("a", "address", "address which server would listen to", "");
    opts.reqopt("p", "port", "port", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(arg) => arg,
        Err(message) => {
            println!("{}", message.to_string());
            print_usage(&args[0], opts);
            ::std::process::exit(1);
        }
    };
    let address = matches.opt_str("a").unwrap();
    let port = matches.opt_str("p").unwrap();
    let mut server: Server;
    match Server::new(address + ":" + port.as_ref()) {
        Ok(bound_server) => server = bound_server,
        Err(message) => panic!("{}", message),
    }
    if let Ok(()) = server.server_loop() {
        println!("Server bind success.");
    } else {
        println!("Oopsie fucky wucky UwU")
    };
}

#[cfg(test)]
mod tests {
    use super::*;

}

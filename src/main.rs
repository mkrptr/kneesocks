extern crate getopts;
extern crate nom;
extern crate regex;
extern crate lazy_static;

use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, ToSocketAddrs,
               IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use getopts::Options;
use std::env;
use std::io::Result;
use std::mem::replace;
use std::cell::RefCell;
use regex::Regex;
use lazy_static::*;
use nom::*;
use nom::number::streaming::be_u8;
use nom::number::streaming::be_u16;

enum RequestAddressType {
    IPv4 = 0x000001,
    DomainName = 0x000003,
    IPv6 = 0x000004,
    InvalidAddress
}
impl From<u8> for RequestAddressType {
    fn from(value: u8) -> Self {
        match value {
            1 => RequestAddressType::IPv4,
            2 => RequestAddressType::DomainName,
            3 => RequestAddressType::IPv6,
            _ => RequestAddressType::InvalidAddress
        }
    }
}

struct SocksConnection {
    dst_socket_addr: SocketAddr,
    server_socket_addr: SocketAddr,
    client_stream: TcpStream
}

impl SocksConnection {
    fn new(client_stream: TcpStream, server_socket_addr: SocketAddr) -> Self {
        SocksConnection {
            client_stream,
            server_socket_addr,
            dst_socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0,0,0,0])), 8080)
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
        let mut buffer: [u8;512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        println!("{:x?}", &buffer[..]);
        let mut address_type: RequestAddressType = RequestAddressType::InvalidAddress;
        let socks_version = buffer[0];
        assert_eq!(socks_version, 5);
        let command = buffer[1];
        println!("request address type: {}", buffer[3]);

        match RequestAddressType::from(buffer[3]) {
            RequestAddressType::IPv4 => {
                named!(parse_ipv4<SocketAddr>,
                       do_parse!(
                           a: be_u8 >>
                           b: be_u8 >>
                           c: be_u8 >>
                           d: be_u8 >>
                           port: be_u16 >>
                           (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
                       ));
                let address = parse_ipv4(&buffer[4..10]);
                if let Ok((_, sock_addr)) = address {
                    address_type = RequestAddressType::IPv4;
                    self.dst_socket_addr = sock_addr;
                } else {
                    return Err(format!("Can't parse ipv4 address : {:?}", &buffer[4..10]));
                }
            },
            RequestAddressType::DomainName => {
                named!(parse_fqdn<String>,
                       do_parse!(
                           fqdn_len: be_u8 >>
                               fqdn: take!(fqdn_len) >>
                               port: take!(2) >>
                               (format!("{}:{}", String::from_utf8_lossy(fqdn),
                                                 String::from_utf8_lossy(port)))));
                let socket_str_res = parse_fqdn(&buffer[4..512]);
                if let Ok((_, socket_str)) = socket_str_res {
                    match socket_str.to_socket_addrs() {
                        Ok(mut sock_iter) => {
                            match sock_iter.next() {
                                Some(sock_addr) => {
                                    address_type = RequestAddressType::DomainName;
                                    self.dst_socket_addr = sock_addr;
                                },
                                None => {
                                    return Err(format!("Couldn't parse fqdn socket address: {}", socket_str));
                                }
                            }
                        },
                        _ => {
                            return Err(format!("Couldn't parse fqdn socket address: {}", socket_str));
                        }
                    }
                }
            },
            RequestAddressType::IPv6 => {
                named!(parse_ipv6<SocketAddr>,
                       do_parse!(
                           a: be_u16 >>
                               b: be_u16 >>
                               c: be_u16 >>
                               d: be_u16 >>
                               e: be_u16 >>
                               f: be_u16 >>
                               g: be_u16 >>
                               h: be_u16 >>
                               port: be_u16 >>
                               (SocketAddr::new(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)), port))));
                let ip_addr_res = parse_ipv6(&buffer[4..20]);
                if let Ok((_, sock_addr)) = ip_addr_res {
                    address_type = RequestAddressType::IPv6;
                    self.dst_socket_addr = sock_addr;
                } else {
                    return Err(format!("Couldn't parse socket addr: {:?}", ip_addr_res));
                }
            },
            RequestAddressType::InvalidAddress => {
                return Err(String::from("Invalid address"));
            }
             
        }

        println!("dst_socket_addr : {}", self.dst_socket_addr);
        //TODO: add support for bind and udpassociate commands
        let mut server_response: [u8;512] = [0;512];
        server_response[0] = socks_version;
        server_response[1] = 0;
        server_response[2] = 0;
        server_response[3] = address_type as u8;
        let mut local_addr_octets: Vec<u8>  = match self.server_socket_addr.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let local_addr_port = self.server_socket_addr.port();
        local_addr_octets.push((local_addr_port >> 8) as u8);
        local_addr_octets.push(local_addr_port as u8);
        server_response[4..4+local_addr_octets.len()]
            .clone_from_slice(local_addr_octets.as_slice());

        println!("Server response: {:x?}", &server_response[..]);
        self.client_stream.write(&server_response[..4+local_addr_octets.len()]);
        self.client_stream.flush();
        //server_response = [socks_version, 0,0,address_type as u8, local_add] 
        //server_stream.write(buf: &[u8])
        Ok(())
    }

    fn authenticate_client(&mut self) -> std::result::Result<(), String>{
        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+

         */
        println!("Authenticating client");
        let mut buffer: [u8;512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        println!("{:x?}", &buffer[..]);
        let socks_version = buffer[0];
        if socks_version != 5 {
            return Err(format!("Expected socks version 5, given: {}", socks_version));
        }
        let number_of_methods = buffer[1];
        if number_of_methods == 0 {
            return Err(String::from("No methods specified"));
        }
        let mut methods: Vec<AuthenticationMethods> = Vec::new();
        for method_byte in 0..number_of_methods {
            methods.push(AuthenticationMethods::from(buffer[2+method_byte as usize]));
        }
        if let Ok(_bytes_written) = self.client_stream.write(&[socks_version,
                                     std::mem::replace(methods.first_mut().unwrap(),
                                     AuthenticationMethods::InvalidMethod) as u8]) {
            //TODO: logs
            self.client_stream.flush();
        }
        println!("Authenticated succesfully");
        Ok(())
    }

    fn perform_request(&mut self) -> std::result::Result<(), String> {
        let mut buffer: [u8;8192] = [0; 8192];
        let mut benis = String::new();
            
       // self.client_stream.read_to_string(&mut benis);
       // println!("{:x?}", benis.as_bytes());
        //return Ok(());
 /*       
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
*/
        let mut bytes_written = match self.client_stream.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => {
                return Err(String::from("Couldn't read from client's stream"));
            }
        };
        println!("{}", String::from_utf8_lossy(&buffer));
        println!("{:x?}", &buffer[..bytes_written]);
        let mut conn: TcpStream = match TcpStream::connect(self.dst_socket_addr) {
            Ok(stream) => {
                println!("Connected to {}", self.dst_socket_addr);
                stream
            },
            Err(message) => {
                return Err(format!("Coudln't connect to destination address. : {}", message));
            }
        };
        conn.write(&buffer[..bytes_written]);
        conn.flush();

        buffer = [0;8192];

        bytes_written = match conn.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => {
                return Err(String::from("Couldn't read from client's stream"));
            }
        };
        println!("entire resp: {:x?}", &buffer[..]);
        //println!("HTTP response is {}", String::from_utf8_lossy(&buffer));
        //println!("bytes are : {:x?}", &buffer[0..bytes_written]);
        if buffer[0] == 0x16 {
            println!("performing tls handshake");
            named!(server_req1<usize>,
                   do_parse!(
                       protocol_type: be_u8 >>
                       version: take!(2) >>
                       length: be_u16 >>
                       ((length + 5) as usize)
                   ));
            let mut next_index: usize = 0;
            if let Ok((_,len)) = server_req1(&buffer) {
                println!("len: {}", len);
                println!("Server hello: \n{:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index = len ;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index += len;
            }
            //println!("next_index after cert: {}", next_index);
            //println!("boof: {:x?}", &buffer[next_index..]);
            if let Ok((_, len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                println!("Server Key Exchange:  \n {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index += len;
            }
            if let Ok((_, len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                println!("Server Hello Done: \n {:x?}",  &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
            }
            println!("sent server part successfully");
            buffer = [0;8192];
            next_index = 0;
            self.client_stream.read(&mut buffer[..]);
            //println!("{:x?}", &buffer[..]);
            if let Ok((_,len)) = server_req1(&buffer) {
                println!("len: {}", len);
                //println!("Server hello: \n{:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index = len ;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index += len;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index += len;
            }
            println!("client handshake finished");
            buffer = [0;8192];
            next_index = 0;
            conn.read(&mut buffer);
            //println!("{:x?}", &buffer[..]);
            if let Ok((_,len)) = server_req1(&buffer) {
                println!("len: {}", len);
                //println!("Server hello: \n{:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index = len ;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index += len;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
            }
            println!("server handshake finished");
            buffer = [0;8192];
            next_index = 0;
            self.client_stream.read(&mut buffer[..]);
            //println!("{:x?}", &buffer[..]);
            if let Ok((_,len)) = server_req1(&buffer) {
                println!("len: {}", len);
                //println!("Server hello: \n{:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index = len ;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index += len;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                conn.write(&buffer[next_index..len+next_index]);
                conn.flush();
                next_index += len;
            }
            println!("ping, i guess");
            buffer = [0;8192];
            next_index = 0;
            conn.read(&mut buffer);
            //println!("{:x?}", &buffer[..]);
            if let Ok((_,len)) = server_req1(&buffer) {
                println!("len: {}", len);
                //println!("Server hello: \n{:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index = len ;
            }
            
            /*
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
                next_index += len;
            }
            if let Ok((_,len)) = server_req1(&buffer[next_index..]) {
                println!("len: {}", len);
                //println!("Server certificate: {:x?}", &buffer[next_index..len+next_index]);
                self.client_stream.write(&buffer[next_index..len+next_index]);
                self.client_stream.flush();
            }
*/
            /*
            bytes_written = match self.client_stream.write(&buffer[0..bytes_written]) {
                Ok(n) => n,
                _ => {
                    return Err(String::from("Couldn't write to client' stream"));
                }
            };
            self.client_stream.flush();
            buffer = [0;8192];
            self.client_stream.read(&mut buffer);
            println!("bytes are: {:x?}", &buffer[..]);
            */
        } else {
            bytes_written = match self.client_stream.write(&buffer[0..bytes_written]) {
                Ok(n) => n,
                _ => {
                    return Err(String::from("Couldn't write to client' stream"));
                }
            };
        }
       
       

        Ok(())
    }
    
    fn handle_connection(&mut self) -> std::result::Result<(), String> {
        self.authenticate_client()?;
        self.process_client_request()?;
        self.perform_request()?;
        Ok(())
    }

    
    fn handle_stream(&mut self) -> std::result::Result<(), String>{
        self.handle_connection()?;
        Ok(())
    }
}

struct Server {
    listener: TcpListener
}

impl Server {
    fn new(full_address: String) -> std::result::Result<Self, String> {
        if let Ok(listener) = TcpListener::bind(&full_address) {
            return Ok(Server {
                listener
            });
        }
        Err(format!("Couldn't bind to address {}", full_address))
    }
    
    fn server_loop(&mut self) -> Result<()> {
        for stream in self.listener.incoming() {
            println!("Attempting to handle connection");
            let mut socks_conn = SocksConnection::new(
                stream.unwrap(),
                self.listener.local_addr().unwrap()
            );
            
            match socks_conn.handle_stream() {
                Ok(()) => {},
                Err(message) => println!("{}", message)
            }
            
            println!("connection closed");
        }
        Ok(())
    }
}

fn stub() {
    /*
    let mut request_string = String::from_utf8_lossy(&buffer);
        println!("{}", request_string);
        lazy_static! {
            static ref ADDRESS_REGEX: Regex = Regex::new(r"(?:Host: )(.+)(?:\s+)")
                .unwrap();
        }
        let host_address = &ADDRESS_REGEX
            .captures(&request_string);
        
        if let Some(ad) = host_address {
            println!("host adress is {}", ad[1].trim_end());
            //ad[1].trim_end()
            let req_str = &ADDRESS_REGEX.replace_all(&request_string, "Host: google.com\r\n");
            let mut conn = TcpStream::connect(format!("{}:80",ad[1].trim_end()))?;
            println!("{}", req_str);
            conn.write(req_str.as_bytes())?;
            conn.flush()?;
            buffer = [0;512];
            conn.read(&mut buffer)?;

            client_stream.write(&mut buffer)?;
        } */

}
enum RequestCommandMode {
    Noop,
    Connect,
    Bind,
    UdpAssociate,
    InvalidMode
}
impl From<u8> for RequestCommandMode {
    fn from(x: u8) -> Self {
        match x {
            0 => RequestCommandMode::Noop,
            1 => RequestCommandMode::Connect,
            2 => RequestCommandMode::Bind,
            3 => RequestCommandMode::UdpAssociate,
            _ => RequestCommandMode::InvalidMode
        }
    }
}

enum AuthenticationMethods {
    NoAuth,
    GSSAPI,
    UsernamePassword,
    InvalidMethod
}

impl From<u8> for AuthenticationMethods {
    fn from(value: u8) -> Self {
        match value {
            0 => AuthenticationMethods::NoAuth,
            1 => AuthenticationMethods::GSSAPI,
            2 => AuthenticationMethods::UsernamePassword,
            _ => AuthenticationMethods::InvalidMethod
        }
    }
}


enum RequestAddress {
    IPv4(i32),
    DomainName(String),
    IPv6(i64)
}



fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}



fn send_version_mismatch() {
    
}



fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() == 1 {
        println!("Usage: kneesocks --address <127.0.0.1> --port <1111>.");
        ::std::process::exit(1);
    }

    let mut opts = Options::new();
    opts.reqopt("a", "address", "address which server would listen to",
                "");
    opts.reqopt("p", "port", "port", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(arg) => {arg}
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
        Ok(bound_server) => {server = bound_server},
        Err(message) => panic!("{}", message)
    }
    if let Ok(()) = server.server_loop() {
        println!("Server bind success.");
    }
    else {
        println!("Oopsie fucky wucky UwU")
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    
}

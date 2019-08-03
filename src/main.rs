extern crate getopts;
extern crate nom;
#[macro_use]
extern crate log;
use getopts::Options;
use nom::number::streaming::be_u16;
use nom::number::streaming::be_u8;
use nom::*;
use std::env;
use std::result::Result;
use std::io::{self,Read, Write, copy};
use std::mem::replace;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, Shutdown};
use std::thread;
use std::thread::JoinHandle;

enum AuthenticationMethod {
    NoAuth,
    GSSAPI,
    UsernamePassword,
    InvalidMethod,
}

impl From<u8> for AuthenticationMethod {
    fn from(value: u8) -> Self {
        match value {
            0 => AuthenticationMethod::NoAuth,
            1 => AuthenticationMethod::GSSAPI,
            2 => AuthenticationMethod::UsernamePassword,
            _ => AuthenticationMethod::InvalidMethod,
        }
    }
}

#[derive(Debug)]
enum RequestAddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
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

#[derive(Debug)]
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

enum SocksError {
    Succeded,
    ServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    InvalidError
}

struct SocksConnection {
    client_stream: TcpStream,
}
fn build_socks_response(socks_version: u8, error_code: u8,
                            address_type: &mut RequestAddressType, address: &SocketAddr)
                        -> Result<([u8;512], usize), String> {
        /*
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        let mut server_response: [u8; 512] = [0; 512];
        server_response[0] = socks_version;
        server_response[1] = error_code;
        server_response[2] = 0; // Reserved
        server_response[3] = std::mem::replace(address_type,
                                               RequestAddressType::InvalidAddress) as u8;
        let mut local_addr_octets: Vec<u8> = match address.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec()
        };
        let local_addr_port = address.port();
        local_addr_octets.push((local_addr_port >> 8) as u8);
        local_addr_octets.push(local_addr_port as u8);
        server_response[4..4 + local_addr_octets.len()]
            .clone_from_slice(local_addr_octets.as_slice());
    return Ok((server_response, 4+local_addr_octets.len()));
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
    fn new(client_stream: TcpStream) -> Self {
        SocksConnection {
            client_stream,
        }
    }
    
    fn establish_connection(&self, dst_socket_addr: SocketAddr) -> Result<TcpStream, u8> {
        /*
        o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
         */
        let error_field: u8;
        let remote_stream = match TcpStream::connect(dst_socket_addr) {
            Ok(stream) => stream,
            Err(err) => {
                error_field = match err.kind() {
                    io::ErrorKind::ConnectionRefused => 5,
                        
                    io::ErrorKind::AddrNotAvailable => 4,

                    io::ErrorKind::Interrupted |
                    io::ErrorKind::BrokenPipe |
                    _ => 1,
                        
                };
                return Err(error_field);
            }
        };
        info!("Connected successfully to {}", dst_socket_addr);
        Ok(remote_stream)
    }
    fn get_request_info(&mut self) ->
        std::result::Result<(u8, RequestCommandMode,  RequestAddressType, SocketAddr), String> {
        /*
          The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
         */
        info!("Processing client's request");
        let mut buffer: [u8; 512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        debug!("Request info raw data: \n{:x?}", &buffer[..]);
        let socks_version = buffer[0];
        let request_command = RequestCommandMode::from(buffer[1]);
        let address_type = RequestAddressType::from(buffer[3]);
        let dst_socket_addr = match address_type {
            RequestAddressType::IPv4       => get_ipv4_address(&buffer[4..])?,
            RequestAddressType::DomainName => get_domain_name(&buffer[4..])?,
            RequestAddressType::IPv6       => get_ipv6_address(&buffer[4..])?,
            RequestAddressType::InvalidAddress => {
                return Err(String::from("Invalid address"));
            }
        };
        Ok((socks_version, request_command, address_type, dst_socket_addr))
    }

    fn authenticate_with_password(&mut self, socks_version: u8) -> bool {
        /*
        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        +----+------+----------+------+----------+
         */
        info!("Authenticating with username-passoword");
        let mut buffer: [u8;512] = [0;512];
        self.client_stream.read(&mut buffer);
        named!(parse_uname_passwd<(String, String)>,
               do_parse!(
                   version: be_u8 >>
                   username_length: be_u8 >>
                   username: take!(username_length) >>
                   password_length: be_u8 >>
                   password: take!(password_length) >>
                   (String::from_utf8_lossy(username).to_string(),
                    String::from_utf8_lossy(password).to_string())
        ));
        if let Ok((_,(username, password))) = parse_uname_passwd(&buffer[..]) {
            if username == String::from("admin") && password == String::from("1234") {
                self.client_stream.write(&[socks_version, 1]);
                self.client_stream.flush();
                return true;
            }
        }
        self.client_stream.write(&[socks_version, 0]);
        self.client_stream.flush();
        return false;
    }

    fn connect_to_socks(&mut self) -> std::result::Result<(), String> {
        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
         */
        info!("Client connected to socks");
        let mut buffer: [u8; 512] = [0; 512];
        if let Err(_) = self.client_stream.read(&mut buffer) {
            return Err(String::from("couldn't read from stream"));
        }
        debug!("Request raw data: {:x?}", &buffer[..]);
        let socks_version = buffer[0];
        if socks_version != 5 {
            return Err(format!(
                "Expected socks version 5, given: {}",
                socks_version
            ));
        }
        let number_of_methods = buffer[1] as usize;
        if number_of_methods == 0 {
            return Err(String::from("No methods specified"));
        }
        let mut authentication_methods = buffer.iter()
            .skip(2)
            .take(number_of_methods)
            .map(|method_byte| AuthenticationMethod::from(*method_byte))
            .collect::<Vec<AuthenticationMethod>>();

        let  selected_method = replace(authentication_methods.first_mut().unwrap(),
                                          AuthenticationMethod::InvalidMethod) as u8;
        self.client_stream
            .write(&[
                socks_version,
                selected_method,
            ])
            .expect("Couldn't write to stream while authenticating");
        self.client_stream.flush().expect("Couldn't flush stream");

        match AuthenticationMethod::from(selected_method) {
            AuthenticationMethod::UsernamePassword => {
                if !self.authenticate_with_password(socks_version) {
                    return Err(String::from("Invalid username or password"));
                }
            },
            _ => {}
        };
        info!("Authenticated succesfully");
        Ok(())
    }

    fn do_connect(&mut self, remote_stream: TcpStream) -> io::Result<()> {
        info!("Performing connect request");
        let mut remote_to_proxy = remote_stream.try_clone()?;
        let mut proxy_to_remote = remote_stream.try_clone()?;
        let mut client_to_proxy = self.client_stream.try_clone()?;
        let mut proxy_to_client = self.client_stream.try_clone()?;

        info!("Redirecting all data between streams");
        
        let to_client_handle: JoinHandle<io::Result<()>> = thread::spawn(move || {
            copy(&mut remote_to_proxy, &mut proxy_to_client)?;
            info!("client_handle finished ");
            remote_to_proxy.shutdown(Shutdown::Read)?;
            proxy_to_client.shutdown(Shutdown::Write)?;
            info!("client_handle closed");
            Ok(())
        });

        let to_remote_handle: JoinHandle<io::Result<()>> = thread::spawn(move || {
            copy(&mut client_to_proxy, &mut proxy_to_remote)?;
            info!("remote_handle finished ");
            client_to_proxy.shutdown(Shutdown::Read)?;
            proxy_to_remote.shutdown(Shutdown::Write)?;
            info!("remote_handle closed");
            Ok(())
        });

        //to_client_handle.join().unwrap()?;
        //to_remote_handle.join().unwrap()?;
        info!("Redirecting finished");
        Ok(())
    }

    fn send_error(&mut self, socks_version: u8, error_code: u8,
                  address_type: &mut RequestAddressType, dst_socket_addr: &SocketAddr) {
        let (response_buf, length) = build_socks_response(socks_version,
                                                          error_code,
                                                          address_type,
                                                          dst_socket_addr)
            .expect("couldn't build response");
        self.client_stream.write(&response_buf[..length]);
        self.client_stream.flush();
        self.client_stream.shutdown(Shutdown::Both);
        
    }

    
    fn handle_stream(&mut self) -> std::result::Result<(), String> {
        self.connect_to_socks()?;
        let (socks_version, command, mut address_type, dst_socket_addr) =
            self.get_request_info()?;
        debug!("Socks version: {}, request command: {:#?}, address type: {:#?}, destination address: {}",
               socks_version, command, address_type, dst_socket_addr);
        
        let remote_stream = match self.establish_connection(dst_socket_addr) {
            Ok(stream) => {
                let (response_buf, length) = build_socks_response(socks_version,
                                                          0,
                                                          &mut address_type,
                                                          &dst_socket_addr)
                    .expect("couldn't build response");
                self.client_stream.write(&response_buf[..length]);
                self.client_stream.flush();

                stream
            },
            Err(err_code) =>  {
                self.send_error(socks_version, err_code, &mut address_type, &dst_socket_addr);
                return Err(String::from("Server fault"));
            }
        };
        match command {
            RequestCommandMode::Connect => {
                if let Err(error) = self.do_connect(remote_stream) {
                    return Err(format!("{:?}", error));
                }
            }
            //TODO: Add support for bind and udpassociate
            RequestCommandMode::Bind => {}
            RequestCommandMode::UdpAssociate => {}
            _ => {}
        }
        Ok(())
    }
}

struct Server {
    listener: TcpListener,
}

impl Server {
    fn new(full_address: String) -> std::result::Result<Self, String> {
        if let Ok(listener) = TcpListener::bind(&full_address) {
            return Ok(Server { listener});
        }
        Err(format!("Couldn't bind to address {}", full_address))
    }

    fn server_loop(&mut self) {
        for stream in self.listener.incoming() {
            info!("Attempting to handle connection");
            let mut socks_conn =
                SocksConnection::new(stream.unwrap());
            thread::spawn(move || {
                match socks_conn.handle_stream() {
                    Ok(()) => {},
                    Err(message) => {
                        socks_conn.client_stream.shutdown(Shutdown::Both);
                        error!("{}", message);
                    }
                }
                info!("connection closed\n");
            });
        }
    }
}




fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}


fn main() {
    env_logger::init();
    let args = env::args().collect::<Vec<String>>();
    if args.len() == 1 {
        println!("Usage: kneesocks --address <127.0.0.1> --port <1111>.");
        ::std::process::exit(1);
    }
    let mut opts = Options::new();
    opts.reqopt("a", "address", "address which server would listen to", "");
    opts.reqopt("p", "port", "port associated with address", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(arg) => arg,
        Err(message) => {
            error!("{}", message.to_string());
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
    server.server_loop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_test_handshake() {
        let mut server = Server::new("127.0.0.1:1337".parse().unwrap())
            .unwrap();
        let mut localhost_stream = TcpStream::connect("127.0.0.1:1337").unwrap();
        let mut buffer: [u8;512] = [0;512];
        let h_server : JoinHandle<()>= thread::spawn(move || {
            server.server_loop();
        });
        let h_client = thread::spawn(move || {
            localhost_stream.write(&[5, 1, AuthenticationMethod::NoAuth as u8]);
            localhost_stream.read(&mut buffer);
            assert!(buffer[0] == 5);
            assert!(buffer[1] == AuthenticationMethod::NoAuth as u8);
            buffer = [0;512];
            localhost_stream.write(&[5, 1, 0, 1, 0x57, 0xf0, 0xbe, 0x43, 1, 0xbb]);
            localhost_stream.read(&mut buffer);
            assert!(&buffer[..10] == &[5, 0, 0, 1, 0x57, 0xf0, 0xbe, 0x43, 1, 0xbb]);
            buffer = [0;512];
            localhost_stream.write_all(
                b"GET sscce.org HTTP/2.0
                  Host: sscce.org
                  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
                  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                  Accept-Language: en-US,en;q=0.5
                  Accept-Encoding: gzip, deflate
                  Referer: https://www.google.com/
                  DNT: 1
                  Connection: keep-alive
                  Upgrade-Insecure-Requests: 1
                  Cache-Control: max-age=0");
            localhost_stream.flush();
            localhost_stream.read(&mut buffer[..]);
            assert!(buffer[0] != 0);
        });
        h_client.join().unwrap();
        return;
    }

    #[test]
    fn localhost_sscce() {
              


    }

}

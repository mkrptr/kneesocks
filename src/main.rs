extern crate getopts;
extern crate reqwest;
extern crate regex;
extern crate lazy_static;

use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use getopts::Options;
use std::env;
use std::io::Result;
use regex::Regex;
use lazy_static::*;




fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn server_loop(full_address: String) -> Result<()> {
    let listener = TcpListener::bind(full_address)?;
    for stream in listener.incoming() {
        match handle_connection(stream?) {
            Ok(_) => println!("handled successfully"),
            Err(error) => println!("error: {}", error)
        }
        println!("connection closed");
    }
    Ok(())
}

fn handle_connection(mut client_stream: TcpStream) -> Result<()>{
    let mut buffer: [u8;512] = [0; 512];
    client_stream.read(&mut buffer)?;
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
    }
    Ok(())
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

    if let Ok(()) = server_loop(address + ":" + port.as_ref()) {

    }
    else {
        println!("Oopsie fucky wucky UwU")
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    
}

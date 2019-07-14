extern crate reqwest;
use std::net::TcpListener;
use std::net::TcpStream;


//fn extract_headers(stream: &TcpStream) ->
pub fn handle_connection() {
    let client = TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in client.incoming() {
        //let headers = extract_headers(&stream);
        
    }
}




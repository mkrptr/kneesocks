enum ParserState {
    Start,
    Command,
    Value,
    Address,
    Port,
    Finish
}

pub struct Config {
    address: String,
    port: String
}

pub struct Parser {
    state: ParserState,
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            state: ParserState::Start
        }
    }
    pub fn parse_args(&mut self, args: Vec<String>) -> Result<Config, String>{
        let mut address = String::new();
        let mut port = String::new();
        let mut index = 0;
        /* for arg in args.iter().skip(1) {
            if arg.starts_with("-") {
                parse_single_arg(&args[index..index+1]);
            }
        } */
        
        Ok(Config {
            address,
            port
        })
    }

   

}

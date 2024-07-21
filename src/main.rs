use clap::Parser;
use std::fs;
use std::io;
use url::Url;
use serde_json::{json};

#[derive(Parser)]
#[command(author = "Iya Rivvikyn", version = "0.1.0", about = "sing-rivert \nv2ray to sing-box config converter", long_about = None)]
struct Args {
    /// Text file input
    #[arg(short, long)]
    file: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let contents = fs::read_to_string(args.file)?;
    
    let mut results = Vec::new();

    for line in contents.lines() {
        if let Ok(url) = Url::parse(line) {
            if let Some(host) = url.host_str() {
                let protocol = url.scheme();
                let uuid = url.username();
                let port = url.port().unwrap_or(443);
                
                results.push(json!({
                    "uuid": uuid,
                    "ip": host,
                    "port": port,
                    "protocol": protocol
                }));
            }
        }
    }

    let output = json!({
        "result": results
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
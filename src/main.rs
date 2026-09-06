mod dns;
mod error;
mod resolver;

use std::{
    net::{IpAddr, SocketAddr},
    process,
};

use clap::Parser;
use owo_colors::OwoColorize;
use tracing::error;
use tracing_subscriber::EnvFilter;

use crate::{
    dns::answer::{RData, ResourceRecord},
    dns::question::RecordType,
    resolver::{Resolver, ResolverConfig},
};

#[derive(Parser)]
#[command(
    name = "resolver",
    version,
    about,
    long_about,
    after_help = "EXAMPLES:\n resolver example.com\n resolver example.com AAAA\n resolver example.com --type TXT --timeout 3"
)]
struct Cli {
    #[arg(value_name = "DOMAIN", help = "Domain name to resolve")]
    domain: String,

    #[arg(
        value_name = "TYPE",
        help = "Record type (A, AAAA, MX, NS, CNAME, SOA, TXT, SRV, ANY)"
    )]
    record_type_pos: Option<String>,

    #[arg(
        short = 't',
        long = "type",
        value_name = "TYPE",
        help = "Record type override (takes precedence over positional)"
    )]
    record_type_flag: Option<String>,

    #[arg(
        short = 's',
        long = "server",
        default_value = "8.8.8.8",
        value_name = "ADDR",
        help = "DNS server address (default: 8.8.8.8)"
    )]
    server: String,

    #[arg(
        short = 'T',
        long = "timeout",
        default_value = "5",
        value_name = "SECS",
        help = "Per-query timeout in seconds [1-60]"
    )]
    timeout: u64,

    #[arg(
        short = 'r',
        long = "retries",
        default_value = "3",
        help = "Maximum retry attempts on timeout"
    )]
    retries: u8,

    #[arg(
        short = 'v',
        long = "verbose",
        action = clap::ArgAction::Count,
        help = "Verbose output (use -v for debug, -vv for trace)"
    )]
    verbose: u8,

    #[arg(short = 'q', long = "quiet", help = "Suppress informational messages")]
    quiet: bool,
}

fn print_results(domain: &str, records: &[ResourceRecord]) {
    const TTL_WIDTH: usize = 8;

    if records.is_empty() {
        println!(
            "{} {} {}",
            "->".yellow(),
            domain.cyan().bold(),
            "has no records of the requested type"
        );
        return;
    }
    println!(
        "{} {} {}",
        "->".yellow(),
        domain.cyan().bold(),
        format!(
            "({} answer{})",
            records.len(),
            if records.len() == 1 { "" } else { "s" }
        )
    );

    for rr in records {
        print!("{}", format_type(&rr.rdata));
        print!("{:<TTL_WIDTH$}", format_ttl(rr.ttl));
        println!("{}", format_rdata(&rr.rdata))
    }
}

fn format_type(rdata: &RData) -> String {
    match rdata {
        RData::A(_) => "A".blue().bold().to_string(),
        RData::Aaaa(_) => "AAAA".blue().bold().to_string(),
        RData::Ns(_) => "NS".magenta().bold().to_string(),
        RData::Cname(_) => "CNAME".yellow().bold().to_string(),
        RData::Soa { .. } => "SOA".red().bold().to_string(),
        RData::Mx { .. } => "MX".green().bold().to_string(),
        RData::Txt(_) => "TXT".cyan().bold().to_string(),
        RData::Srv { .. } => "SRV".purple().bold().to_string(),
        RData::Unknown(_) => "?".white().bold().to_string(),
    }
}

fn format_ttl(ttl: i32) -> String {
    if ttl < 0 {
        return "-".dimmed().to_string();
    }

    let ttl = ttl as u32;
    if ttl > 3600 {
        format!("{}h", ttl / 3600).dimmed().to_string()
    } else if ttl >= 60 {
        format!("{}m", ttl / 60).dimmed().to_string()
    } else {
        format!("{ttl}s").dimmed().to_string()
    }
}

fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(addr) => addr.to_string().green().to_string(),
        RData::Aaaa(addr) => addr.to_string().green().to_string(),
        RData::Ns(ns) => ns.bright_white().to_string(),
        RData::Cname(target) => format!("-> {}", target.bright_white()),
        RData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            format!(
                "MNAME={mname} RNAME={rname}\n
                SERIAL={serial} REFRESH={refresh}\n 
                RETRY={retry} EXPIRE={expire} MINIMUM={minimum}"
            )
        }
        RData::Mx {
            preference,
            exchange,
        } => format!("{preference} {}", exchange.bright_white()),
        RData::Txt(strings) => strings
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(" "),
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!(
            "
        priority={priority} weight={weight} port={port} target={}
            ",
            target.bright_white()
        ),
        RData::Unknown(bytes) => format!(
            "
                <{} bytes of unknown data>
                    ",
            bytes.len()
        )
        .dimmed()
        .to_string(),
    }
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    if let Some(stripped) = s.strip_prefix('[') {
        if let Some((ip_part, port_part)) = stripped.split_once("]:") {
            let ip: IpAddr = ip_part
                .parse()
                .map_err(|_| format!("invalid ipv6 address: {ip_part}"))?;
            let port: u16 = port_part
                .parse()
                .map_err(|_| format!("invalid port: {port_part}"))?;

            return Ok(SocketAddr::new(ip, port));
        }
    }

    Err(format!(
        "
    could not parse {s} as an IP address or socket address
            "
    ))
}

fn main() {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => EnvFilter::new(if cli.quiet { "error" } else { "warn" }),
        1 => EnvFilter::new("debug"),
        _ => EnvFilter::new("trace"),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let type_str = cli
        .record_type_flag
        .as_deref()
        .or(cli.record_type_pos.as_deref())
        .unwrap_or("A");

    let Some(qtype) = RecordType::from_str(type_str) else {
        error!(
            "Unknown record type: '{type_str}'
            , valid types: A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, ANY"
        );
        process::exit(2);
    };

    let server_addr = match parse_socket_addr(&cli.server) {
        Ok(addr) => addr,
        Err(e) => {
            error!("invalid server address: {} - {e}", cli.server);
            process::exit(2);
        }
    };

    // let cli.timeout < 1 || cli.timeout > 60 {
    //     process::exit(2);
    // }

    let config = ResolverConfig {
        server: server_addr,
        timeout_secs: cli.timeout,
        max_retries: cli.retries,
    };

    let resolver = match Resolver::new(config) {
        Ok(r) => r,
        Err(e) => {
            process::exit(1);
        }
    };

    let answers = match resolver.lookup(&cli.domain, qtype) {
        Ok(records) => records,
        Err(e) => {
            process::exit(1);
        }
    };

    print_results(&cli.domain, &answers);
}

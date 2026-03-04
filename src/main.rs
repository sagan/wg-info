use clap::Parser;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, IsTerminal};
use std::process::{Command, Stdio};
use std::thread;

#[derive(Parser)]
#[command(
    name = "wg-info",
    about = "Wireguard Info\n==============\n\nThis tool enhances the output of 'wg show' to include node names.\nAlso it can ping the nodes (using the first ip in AllowedIPs)\nand indicate the online status via red/green color coding.\n\nIt expects you to use wg-quick and reads the wg-quick config at\n/etc/wireguard/INTERFACE.conf\n\nThe human readable peer names are expected in the wg-quick config \nwithin a comment like this:\n[Peer]\n# Name = Very secret node in antarctica",
    version = "v0.1.1",
    long_about = None
)]
struct Cli {
    /// Format output as HTML
    #[arg(long)]
    html: bool,

    /// Force terminal colors even when writing to pipe
    #[arg(long)]
    tty: bool,

    /// Ping all nodes (in parallel) and show online status
    #[arg(short, long)]
    ping: bool,

    /// Only show status for this interface
    #[arg(short, long)]
    interface: Option<String>,

    /// Filter peers by name or allowed ips
    #[arg(short, long)]
    filter: Option<String>,
}

#[derive(Clone)]
struct PeerInfo {
    name: String,
    ip: String,
    online: bool,
}

#[derive(Clone, Copy)]
struct Colors {
    red: &'static str,
    red_bld: &'static str,
    green: &'static str,
    green_bld: &'static str,
    yellow: &'static str,
    yellow_bld: &'static str,
    bld: &'static str,
    end: &'static str,
}

impl Colors {
    fn html() -> Self {
        Self {
            red: r#"<span style="color: red;">"#,
            red_bld: r#"<span style="color: red; font-weight: bold;">"#,
            green: r#"<span style="color: green;">"#,
            green_bld: r#"<span style="color: green; font-weight: bold;">"#,
            yellow: r#"<span style="color: orange;">"#,
            yellow_bld: r#"<span style="color: orange; font-weight: bold;">"#,
            bld: r#"<span style="font-weight: bold;">"#,
            end: r#"</span>"#,
        }
    }

    fn tty() -> Self {
        Self {
            red: "\x1b[0;31m",
            red_bld: "\x1b[1;31m",
            green: "\x1b[0;32m",
            green_bld: "\x1b[1;32m",
            yellow: "\x1b[0;33m",
            yellow_bld: "\x1b[1;33m",
            bld: "\x1b[1m",
            end: "\x1b[0m",
        }
    }

    fn pipe() -> Self {
        Self {
            red: "",
            red_bld: "",
            green: "",
            green_bld: "",
            yellow: "",
            yellow_bld: "",
            bld: "",
            end: "",
        }
    }
}

fn read_config(interface: &str, peers: &mut HashMap<String, PeerInfo>) {
    let path = format!("/etc/wireguard/{}.conf", interface);
    let Ok(file) = File::open(&path) else { return };
    let reader = BufReader::new(file);

    let mut peer_section = false;
    let mut peer_name = String::from("*nameless*");
    let mut peer_pubkey = String::new();
    let mut peer_ip = String::new();

    let re_name = Regex::new(r"^#?\s*Name").unwrap();

    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line == "[Peer]" {
            if peer_section && !peer_pubkey.is_empty() {
                peers.insert(
                    peer_pubkey.clone(),
                    PeerInfo {
                        name: peer_name.clone(),
                        ip: peer_ip.clone(),
                        online: true,
                    },
                );
                peer_name = String::from("*nameless*");
                peer_pubkey.clear();
                peer_ip.clear();
            }
            peer_section = true;
            continue;
        }

        if peer_section {
            if line.starts_with("PublicKey") {
                peer_pubkey = line.splitn(2, '=').nth(1).unwrap_or("").trim().to_string();
            } else if re_name.is_match(line) {
                peer_name = line.splitn(2, '=').nth(1).unwrap_or("").trim().to_string();
            } else if line.starts_with("AllowedIPs") && peer_ip.is_empty() {
                let ips = line.splitn(2, '=').nth(1).unwrap_or("").trim();
                let first_ip = ips.split(',').next().unwrap_or("").trim();
                peer_ip = first_ip.split('/').next().unwrap_or("").trim().to_string();
            }
        }
    }

    if peer_section && !peer_pubkey.is_empty() {
        peers.insert(
            peer_pubkey,
            PeerInfo {
                name: peer_name,
                ip: peer_ip,
                online: true,
            },
        );
    }
}

fn get_up_interfaces(interfaces: &[String]) -> Vec<String> {
    let Ok(output) = Command::new("ip").arg("link").output() else {
        return vec![];
    };
    let out_str = String::from_utf8_lossy(&output.stdout);
    let mut up = Vec::new();

    let re = Regex::new(r"(?m)^\s?\d+: .*:[^\n]+").unwrap();
    for mat in re.find_iter(&out_str) {
        let parts: Vec<&str> = mat.as_str().split(':').collect();
        if parts.len() >= 2 {
            let iface = parts[1].trim().to_string();
            if interfaces.contains(&iface) {
                up.push(iface);
            }
        }
    }
    up
}

fn get_interface_ips(interface: &str) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["addr", "show", "dev", interface])
        .output()
    {
        let out_str = String::from_utf8_lossy(&output.stdout);
        for line in out_str.lines() {
            let line = line.trim();
            if line.starts_with("inet ") || line.starts_with("inet6 ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    ips.push(parts[1].to_string());
                }
            }
        }
    }
    ips
}

/// Returns true if something was printed to stdout
fn show_info(
    interface: &str,
    peers: &HashMap<String, PeerInfo>,
    colors: &Colors,
    filter: Option<&str>,
    is_first_print: bool,
) -> bool {
    let output = Command::new("wg")
        .args(["show", interface])
        .output()
        .unwrap();
    let out_str = String::from_utf8_lossy(&output.stdout);

    let mut interface_lines = Vec::new();
    let mut peer_blocks: Vec<Vec<String>> = Vec::new();
    let mut current_block = &mut interface_lines;

    // Group output into an interface header and subsequent peer blocks
    for line in out_str.lines() {
        if line.trim().starts_with("peer:") {
            peer_blocks.push(Vec::new());
            current_block = peer_blocks.last_mut().unwrap();
        }
        current_block.push(line.to_string());
    }

    // Filter peer blocks based on name or AllowedIPs
    let mut filtered_blocks = Vec::new();
    for block in peer_blocks {
        if let Some(f) = filter {
            let f_lower = f.to_lowercase();
            let pubkey = block[0].splitn(2, ':').nth(1).unwrap_or("").trim();
            let name = peers
                .get(pubkey)
                .map(|p| p.name.clone())
                .unwrap_or_default();

            let mut match_found = name.to_lowercase().contains(&f_lower);

            if !match_found {
                for line in &block {
                    let trimmed = line.trim();
                    if trimmed.starts_with("allowed ips:")
                        && trimmed.to_lowercase().contains(&f_lower)
                    {
                        match_found = true;
                        break;
                    }
                }
            }

            if !match_found {
                continue; // Skip this peer block
            }
        }
        filtered_blocks.push(block);
    }

    // Hide the interface completely if filtering is active and no peers match
    if filter.is_some() && filtered_blocks.is_empty() {
        return false;
    }

    // Ensure proper visual spacing between interfaces
    if !is_first_print {
        println!("\n");
    }

    // Print interface header
    for line in interface_lines {
        let line = line.trim();
        if line.starts_with("interface:") {
            let iface = line.splitn(2, ':').nth(1).unwrap_or("").trim();
            println!(
                "{}interface{}: {}{}{}",
                colors.yellow_bld, colors.end, colors.yellow, iface, colors.end
            );

            let ips = get_interface_ips(iface);
            if !ips.is_empty() {
                println!("  {}address{}: {}", colors.bld, colors.end, ips.join(", "));
            }
        } else if line.starts_with("preshared key:") || line.starts_with("private key:") {
            continue;
        } else if !line.is_empty() {
            let mut parts = line.splitn(2, ':');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                println!(
                    "  {}{}{}: {}",
                    colors.bld,
                    key.trim(),
                    colors.end,
                    value.trim()
                );
            } else {
                println!("{}", line);
            }
        }
    }

    // Print matched peers
    for block in filtered_blocks {
        for line in block {
            let line = line.trim();
            if line.starts_with("peer:") {
                let pubkey = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                if let Some(info) = peers.get(pubkey) {
                    let (colorfmt, colorbldfmt) = if info.online {
                        (colors.green, colors.green_bld)
                    } else {
                        (colors.red, colors.red_bld)
                    };
                    println!(
                        "  {}peer{}: {}{} ({}){}",
                        colorbldfmt, colors.end, colorfmt, info.name, pubkey, colors.end
                    );
                } else {
                    println!("  {}peer{}: {}", colors.bld, colors.end, pubkey);
                }
            } else if line.starts_with("preshared key:") || line.starts_with("private key:") {
                continue;
            } else if !line.is_empty() {
                let mut parts = line.splitn(2, ':');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    println!(
                        "\t{}{}{}: {}",
                        colors.bld,
                        key.trim(),
                        colors.end,
                        value.trim()
                    );
                } else {
                    println!("{}", line);
                }
            }
        }
    }

    true
}

fn main() {
    let cli = Cli::parse();

    let colors = if cli.html {
        Colors::html()
    } else if cli.tty || std::io::stdout().is_terminal() {
        Colors::tty()
    } else {
        Colors::pipe()
    };

    if unsafe { libc::geteuid() } != 0 {
        println!(
            "\n{}ERROR: {}The script must run as root\n{}",
            colors.red_bld, colors.yellow, colors.end
        );
        std::process::exit(-1);
    }

    let mut interfaces = Vec::new();
    if let Some(iface) = &cli.interface {
        interfaces.push(iface.clone());
    } else if let Ok(entries) = fs::read_dir("/etc/wireguard/") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "conf") {
                if let Some(stem) = path.file_stem() {
                    interfaces.push(stem.to_string_lossy().to_string());
                }
            }
        }
    }

    let interfaces = get_up_interfaces(&interfaces);
    let mut peers: HashMap<String, PeerInfo> = HashMap::new();

    for interface in &interfaces {
        read_config(interface, &mut peers);
    }

    if cli.ping {
        let (tx, rx) = std::sync::mpsc::channel();
        for (pubkey, info) in peers.iter() {
            let ip = info.ip.clone();
            let pubkey = pubkey.clone();
            let tx = tx.clone();

            if ip.is_empty() {
                continue;
            }

            thread::spawn(move || {
                let status = Command::new("ping")
                    .args(["-c1", "-W1", &ip])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let online = status.map(|s| s.success()).unwrap_or(false);
                let _ = tx.send((pubkey, online));
            });
        }
        drop(tx);
        for (pubkey, online) in rx {
            if let Some(info) = peers.get_mut(&pubkey) {
                info.online = online;
            }
        }
    }

    if cli.html {
        println!("<pre>");
    }

    let mut is_first = true;
    for interface in &interfaces {
        let printed = show_info(interface, &peers, &colors, cli.filter.as_deref(), is_first);
        if printed {
            is_first = false;
        }
    }

    if cli.html {
        println!("</pre>");
    }
}

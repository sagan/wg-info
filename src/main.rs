use clap::Parser;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, IsTerminal};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;

#[derive(Parser)]
#[command(
    name = "wg-info",
    about = "Wireguard Info\n==============\n\nThis tool enhances the output of 'wg show' to include node names.\nAlso it can ping the nodes (using the first ip in AllowedIPs)\nand indicate the online status via red/green color coding.\n\nIt expects you to use wg-quick and reads the wg-quick config at\n/etc/wireguard/INTERFACE.conf\n\nThe human readable peer names are expected in the wg-quick config \nwithin a comment like this:\n[Peer]\n# Name = Very secret node in antarctica",
    version,
    long_about = None
)]
struct Cli {
    /// Format output as HTML
    #[arg(long)]
    html: bool,

    /// Force terminal colors even when writing to pipe
    #[arg(long)]
    tty: bool,

    /// Ping all nodes (in parallel) and show online status. It uses system ping command.
    #[arg(short, long)]
    ping: bool,

    /// Ping all peers with max payload size based on interface MTU, and show the actual MTU
    /// This will also show the MTU status for the interface. It uses raw sockets to ping.
    #[arg(short = 'P', long)]
    ping_mtu: bool,

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
    interface: String,
    actual_mtu: Option<usize>,
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
                        interface: interface.to_string(),
                        actual_mtu: None,
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
                interface: interface.to_string(),
                actual_mtu: None,
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

fn get_interface_mtu(interface: &str) -> Option<usize> {
    let output = Command::new("ip").args(["addr", "show", "dev", interface]).output().ok()?;
    let out_str = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"mtu\s+(\d+)").unwrap();
    if let Some(caps) = re.captures(&out_str) {
        if let Ok(mtu) = caps[1].parse::<usize>() {
            return Some(mtu);
        }
    }
    None
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() {
        let word = if i + 1 < data.len() {
            (data[i] as u32) << 8 | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum += word;
        i += 2;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ping_raw_mtu(ip: &str, mtu: usize, ident: u16) -> bool {
    let ipv4 = match Ipv4Addr::from_str(ip) {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return false;
    }

    let pmtu = 2i32; // IP_PMTUDISC_DO
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &pmtu as *const _ as *const libc::c_void,
            std::mem::size_of_val(&pmtu) as libc::socklen_t,
        );
    }

    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
    }

    let payload_size = mtu.saturating_sub(28);
    let packet_size = 8 + payload_size;
    let mut packet = vec![0u8; packet_size];
    packet[0] = 8;
    packet[1] = 0;
    packet[4] = (ident >> 8) as u8;
    packet[5] = (ident & 0xff) as u8;
    packet[6] = 0;
    packet[7] = 1;

    for i in 8..packet_size {
        packet[i] = (i & 0xff) as u8;
    }

    let sum = checksum(&packet);
    packet[2] = (sum >> 8) as u8;
    packet[3] = (sum & 0xff) as u8;

    let dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ipv4.octets()),
        },
        sin_zero: [0; 8],
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&dest) as libc::socklen_t,
        )
    };

    if sent < 0 {
        unsafe { libc::close(fd) };
        return false;
    }

    let mut recv_buf = vec![0u8; 65536];
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() >= 1 {
            break;
        }

        let n = unsafe {
            libc::recvfrom(
                fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n > 0 {
            let n = n as usize;
            if n >= 20 {
                let ihl = (recv_buf[0] & 0x0f) as usize * 4;
                if n >= ihl + 8 {
                    let icmp_type = recv_buf[ihl];
                    if icmp_type == 0 {
                        let recv_ident = ((recv_buf[ihl + 4] as u16) << 8) | (recv_buf[ihl + 5] as u16);
                        if recv_ident == ident {
                            unsafe { libc::close(fd) };
                            return true;
                        }
                    }
                }
            }
        } else {
            break;
        }
    }

    unsafe { libc::close(fd) };
    false
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
    is_ping_mtu: bool,
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

            if is_ping_mtu {
                let expected_mtu = get_interface_mtu(iface).unwrap_or(1500);

                let mut online_mtus = Vec::new();
                for info in peers.values() {
                    if info.interface == iface && info.online {
                        if let Some(mtu) = info.actual_mtu {
                            online_mtus.push(mtu);
                        }
                    }
                }

                if online_mtus.is_empty() {
                    println!(
                        "  {}mtu status{}: {}no online peers to evaluate{} (expected: {})",
                        colors.bld, colors.end, colors.yellow, colors.end, expected_mtu
                    );
                } else {
                    let min_working_mtu = *online_mtus.iter().min().unwrap();
                    let (status_color, status_text) = if min_working_mtu >= expected_mtu {
                        (colors.green, "OK")
                    } else {
                        (colors.red, "NOT OK")
                    };

                    println!(
                        "  {}mtu status{}: {}{}{} (actual allowed max: {}, expected: {})",
                        colors.bld, colors.end, status_color, status_text, colors.end, min_working_mtu, expected_mtu
                    );
                }
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
                    if info.online {
                        if is_ping_mtu {
                            let expected_mtu = get_interface_mtu(&info.interface).unwrap_or(1500);
                            let actual_mtu = info.actual_mtu.unwrap_or(0);

                            let mtu_str = if actual_mtu >= expected_mtu {
                                format!("{}{} MTU OK ({}){}", colors.green, colors.bld, actual_mtu, colors.end)
                            } else {
                                format!("{}{} MTU FAILED (max {}){}", colors.red, colors.bld, actual_mtu, colors.end)
                            };

                            println!(
                                "  {}peer{}: {}{} ({}) (online, {}){}",
                                colorbldfmt, colors.end, colorfmt, info.name, pubkey, mtu_str, colors.end
                            );
                        } else {
                            println!(
                                "  {}peer{}: {}{} ({}) (online){}",
                                colorbldfmt, colors.end, colorfmt, info.name, pubkey, colors.end
                            );
                        }
                    } else {
                        if is_ping_mtu {
                            println!(
                                "  {}peer{}: {}{} ({}) (offline/no MTU){}",
                                colorbldfmt, colors.end, colorfmt, info.name, pubkey, colors.end
                            );
                        } else {
                            println!(
                                "  {}peer{}: {}{} ({}){}",
                                colorbldfmt, colors.end, colorfmt, info.name, pubkey, colors.end
                            );
                        }
                    }
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

    if cli.ping || cli.ping_mtu {
        let (tx, rx) = std::sync::mpsc::channel();
        let ident_counter = std::sync::Arc::new(AtomicU16::new(1));

        let mut interface_mtus = HashMap::new();
        if cli.ping_mtu {
            for interface in &interfaces {
                if let Some(mtu) = get_interface_mtu(interface) {
                    interface_mtus.insert(interface.clone(), mtu);
                }
            }
        }

        for (pubkey, info) in peers.iter() {
            let ip = info.ip.clone();
            let pubkey = pubkey.clone();
            let tx = tx.clone();
            let is_ping_mtu = cli.ping_mtu;
            // Provide a default MTU in case extracting MTU failed or interface was somehow missed.
            let expected_mtu = interface_mtus.get(&info.interface).copied().unwrap_or(1500);
            let ident_counter = ident_counter.clone();

            if ip.is_empty() {
                continue;
            }

            thread::spawn(move || {
                let (online, actual_mtu) = if is_ping_mtu {
                    if ping_raw_mtu(&ip, expected_mtu, ident_counter.fetch_add(1, Ordering::SeqCst)) {
                        (true, Some(expected_mtu))
                    } else if !ping_raw_mtu(&ip, 1200, ident_counter.fetch_add(1, Ordering::SeqCst)) {
                        (false, None)
                    } else {
                        let mut low = 1201;
                        let mut high = expected_mtu - 1;
                        let mut max_working = 1200;
                        while low <= high {
                            let mid = low + (high - low) / 2;
                            if ping_raw_mtu(&ip, mid, ident_counter.fetch_add(1, Ordering::SeqCst)) {
                                max_working = mid;
                                low = mid + 1;
                            } else {
                                high = mid - 1;
                            }
                        }
                        (true, Some(max_working))
                    }
                } else {
                    let status = Command::new("ping")
                        .args(["-c1", "-W1", &ip])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    (status.map(|s| s.success()).unwrap_or(false), None)
                };
                let _ = tx.send((pubkey, online, actual_mtu));
            });
        }
        drop(tx);
        for (pubkey, online, actual_mtu) in rx {
            if let Some(info) = peers.get_mut(&pubkey) {
                info.online = online;
                info.actual_mtu = actual_mtu;
            }
        }
    }

    if cli.html {
        println!("<pre>");
    }

    let mut is_first = true;
    for interface in &interfaces {
        let printed = show_info(interface, &peers, &colors, cli.filter.as_deref(), is_first, cli.ping_mtu);
        if printed {
            is_first = false;
        }
    }

    if cli.html {
        println!("</pre>");
    }
}

use std::env;
use std::process::Command;
use std::str;

/* --- 常量定义 --- */
const DEFAULT_PORTS: [u16; 1] = [3000];

/* --- 主函数 --- */
fn main() {
    // 从命令行参数获取端口号列表，如果没有提供则使用默认端口
    let ports = parse_ports_from_args();
    
    println!("🚀 WSL2 端口转发工具 v1.0 (Rust版)");
    println!("目标端口: {:?}", ports);

    // 检查是否以管理员权限运行（Windows）
    if !is_admin() {
        eprintln!("❌ 此脚本必须以管理员权限运行！");
        eprintln!("   右键点击此 .exe 文件并选择'以管理员身份运行'。");
        std::process::exit(1);
    }
    println!("✅ 已确认管理员权限");

    // 获取 WSL2 的 IP 地址
    let wsl_ip = match get_wsl_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("❌ 获取 WSL2 IP 失败: {}", e);
            std::process::exit(1);
        }
    };
    println!("✅ WSL IP: {}", wsl_ip);

    // 显示所有网络接口信息
    match show_all_network_interfaces() {
        Ok(_) => (),
        Err(e) => eprintln!("⚠️  获取网络接口信息失败: {}", e),
    }

    // 处理每个端口
    let mut all_success = true;
    for port in &ports {
        // 删除旧的端口转发规则
        if let Err(e) = delete_port_proxy(*port) {
            eprintln!("⚠️  警告: 删除端口 {} 的旧规则失败: {}", port, e);
            // 不退出，继续尝试添加新规则
        }
        println!("🧹 已清理端口 {} 的旧端口代理规则", port);

        // 添加新规则
        if let Err(e) = add_port_proxy(*port, &wsl_ip) {
            eprintln!("❌ 添加端口 {} 的端口代理规则失败: {}", port, e);
            all_success = false;
            continue;
        }
        println!("🔁 已添加端口转发: 0.0.0.0:{} → {}:{}", port, wsl_ip, port);

        // 创建或更新防火墙规则
        if let Err(e) = ensure_firewall_rule(*port) {
            eprintln!("❌ 配置端口 {} 的防火墙规则失败: {}", port, e);
            all_success = false;
            continue;
        }
        println!("🛡️  防火墙规则已配置: WSL 端口 {}", port);
    }

    // 获取主机所有局域网 IP
    match get_all_lan_ips() {
        Ok(ips) if !ips.is_empty() => {
            println!("\n🌐 局域网访问地址:");
            for (interface, ip) in ips {
                for port in &ports {
                    println!("   {}: http://{}:{}", interface, ip, port);
                }
            }
        },
        Ok(_) => {
            println!("⚠️  未找到有效的局域网 IP。请检查网络或 VPN。");
            for port in &ports {
                println!("💡 尝试访问: http://localhost:{}", port);
            }
        },
        Err(e) => {
            println!("⚠️  检测局域网 IP 失败: {}", e);
            for port in &ports {
                println!("💡 尝试访问: http://localhost:{}", port);
            }
        }
    }

    println!("\n💡 重要提示:");
    for port in ports {
        println!("   • 您在 WSL 内的服务必须绑定到 0.0.0.0:{}", port);
    }
    println!("   • 示例: npm run dev -- --host 0.0.0.0");
    println!("   • 如果无法访问: 使用 'wsl --shutdown' 重启 WSL");
    
    if all_success {
        println!("\n🎉 所有端口设置完成！");
    } else {
        println!("\n⚠️  部分端口设置失败，请检查错误信息！");
    }
}

/* --- 从命令行参数解析端口列表 --- */
fn parse_ports_from_args() -> Vec<u16> {
    let args: Vec<String> = env::args().skip(1).collect();
    
    if args.is_empty() {
        return DEFAULT_PORTS.to_vec();
    }
    
    let mut ports = Vec::new();
    for arg in args {
        // 检查是否是端口范围，如 8000-8010
        if arg.contains('-') {
            let parts: Vec<&str> = arg.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    if start <= end {
                        for port in start..=end {
                            ports.push(port);
                        }
                        continue;
                    }
                }
            }
            eprintln!("❌ 无效的端口范围: {}", arg);
            continue;
        }
        
        // 单个端口
        match arg.parse::<u16>() {
            Ok(port) => ports.push(port),
            Err(_) => {
                eprintln!("❌ 无效的端口号: {}", arg);
            }
        }
    }
    
    // 如果没有有效的端口，使用默认端口
    if ports.is_empty() {
        eprintln!("⚠️  没有有效的端口参数，使用默认端口");
        return DEFAULT_PORTS.to_vec();
    }
    
    ports
}

/* --- 检查是否为管理员 --- */
fn is_admin() -> bool {
    match Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()
    {
        Ok(output) => {
            if let Ok(stdout) = str::from_utf8(&output.stdout) {
                stdout.trim() == "True"
            } else {
                false
            }
        }
        Err(_) => false, // 如果命令执行失败（如 PowerShell 不存在），默认不是管理员
    }
}

/* --- 获取 WSL2 的 IPv4 地址（取第一个非 Docker/VM 的）--- */
fn get_wsl_ip() -> Result<String, String> {
    let output = Command::new("wsl")
        .arg("hostname")
        .arg("-I")
        .output()
        .map_err(|e| format!("执行 wsl 命令失败: {}", e))?;

    if !output.status.success() {
        return Err("WSL 命令执行失败".to_string());
    }

    let stdout = str::from_utf8(&output.stdout)
        .map_err(|e| format!("WSL 输出的 UTF-8 无效: {}", e))?
        .trim();

    let ips: Vec<&str> = stdout.split_whitespace().collect();
    // 使用引用迭代，避免所有权转移
    for ip in &ips {
        if is_valid_ipv4(ip) {
            // 排除 Docker 和 VMware 虚拟网络
            if !ip.starts_with("172.17.")
                && !ip.starts_with("172.18.")
                && !ip.starts_with("172.19.")
                && !ip.starts_with("192.168.")
            {
                return Ok(ip.to_string());
            }
        }
    }

    // 如果没有排除的，取第一个合法 IP
    for ip in ips {
        if is_valid_ipv4(ip) {
            return Ok(ip.to_string());
        }
    }

    Err("在 WSL 中未找到有效的 IPv4 地址".to_string())
}

/* --- 验证是否是有效的IP4地址 */
fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    true
}

/* --- 删除 netsh 端口转发规则 --- */
fn delete_port_proxy(port: u16) -> Result<(), String> {
    let output = Command::new("netsh")
        .args(&[
            "interface",
            "portproxy",
            "delete",
            "v4tov4",
            &format!("listenport={}", port),
            "listenaddress=0.0.0.0",
        ])
        .output()
        .map_err(|e| format!("netsh 删除失败: {}", e))?;

    if !output.status.success() {
        // 允许失败（规则不存在是正常情况）
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<无效>");
        if !stderr.contains("找不到指定的接口") {
            return Err(format!("netsh 删除返回错误: {}", stderr));
        }
    }
    Ok(())
}

/* --- 添加 netsh 端口转发规则 --- */
fn add_port_proxy(port: u16, connect_address: &str) -> Result<(), String> {
    let output = Command::new("netsh")
        .args(&[
            "interface",
            "portproxy",
            "add",
            "v4tov4",
            &format!("listenport={}", port),
            "listenaddress=0.0.0.0",
            &format!("connectport={}", port),
            &format!("connectaddress={}", connect_address),
        ])
        .output()
        .map_err(|e| format!("netsh 添加失败: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<无效>");
        return Err(format!("netsh 添加失败: {}", stderr));
    }
    Ok(())
}

/* --- 确保防火墙规则存在 --- */
fn ensure_firewall_rule(port: u16) -> Result<(), String> {
    let rule_name = format!("WSL 端口 {}", port);

    // 检查规则是否存在
    let output = Command::new("netsh")
        .args(&[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &rule_name,
            "name=all",
        ])
        .output()
        .map_err(|e| format!("netsh 显示规则失败: {}", e))?;

    let stdout = str::from_utf8(&output.stdout).unwrap_or("");
    let exists = stdout.contains(&rule_name);

    if exists {
        println!("✅ 防火墙规则已存在: {}", rule_name);
        return Ok(());
    }

    // 创建规则
    let output = Command::new("netsh")
        .args(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=allow",
            &format!("protocol=TCP"),
            &format!("localport={}", port),
        ])
        .output()
        .map_err(|e| format!("netsh 添加防火墙规则失败: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<无效>");
        return Err(format!("创建防火墙规则失败: {}", stderr));
    }

    println!("✅ 防火墙规则已创建: {}", rule_name);
    Ok(())
}

/* --- 显示所有网络接口信息 --- */
fn show_all_network_interfaces() -> Result<(), String> {
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            r#"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress | Format-Table -AutoSize"#,
        ])
        .output()
        .map_err(|e| format!("PowerShell 命令失败: {}", e))?;

    if !output.status.success() {
        return Err("执行 PowerShell 查询失败".to_string());
    }

    let output_str = str::from_utf8(&output.stdout)
        .map_err(|e| format!("PowerShell 输出的 UTF-8 无效: {}", e))?;
    
    println!("\n📶 活动网络接口:");
    println!("{}", output_str);
    
    Ok(())
}

/* --- 获取主机所有局域网 IP（按网卡分组）--- */
fn get_all_lan_ips() -> Result<Vec<(String, String)>, String> {
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            r#"Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } | Select-Object InterfaceAlias, IPAddress | Sort-Object InterfaceAlias | Format-Table @{Label='网卡名称';Expression={$_.InterfaceAlias}}, @{Label='IP地址';Expression={$_.IPAddress}} -HideTableHeaders"#,
        ])
        .output()
        .map_err(|e| format!("PowerShell 命令失败: {}", e))?;

    if !output.status.success() {
        return Err("执行 PowerShell 查询失败".to_string());
    }

    let output_str = str::from_utf8(&output.stdout)
        .map_err(|e| format!("PowerShell 输出的 UTF-8 无效: {}", e))?;
    
    let mut results = Vec::new();
    for line in output_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        
        // 分割网卡名称和IP地址
        if let Some(pos) = trimmed.find(char::is_whitespace) {
            let interface = trimmed[..pos].trim().to_string();
            let ip_parts: Vec<&str> = trimmed[pos..].split_whitespace().collect();
            
            for ip_part in ip_parts {
                if is_valid_ipv4(ip_part) {
                    results.push((interface.clone(), ip_part.to_string()));
                    break;
                }
            }
        }
    }
    
    Ok(results)
}
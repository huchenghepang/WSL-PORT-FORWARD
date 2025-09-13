# WSL 端口转发工具

这是一个用 Rust 编写的 WSL (Windows Subsystem for Linux) 端口转发工具，用于在 Windows 和 WSL 之间设置网络端口转发，方便在本地网络中访问 WSL 中运行的服务。

## 功能特点

- 自动获取 WSL 的 IP 地址
- 支持指定单个端口或端口范围进行转发
- 自动配置 Windows 防火墙规则
- 自动设置端口代理规则
- 支持查看所有网络接口的 IP 地址
- 以管理员权限运行所需的操作

## 系统要求

- Windows 10 或 Windows 11
- WSL 已安装并启用
- 已安装 Rust 环境（仅用于编译）

## 安装指南

### 从源码编译

1. 确保已安装 Rust 环境：

```bash
# 安装 Rust（如果尚未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. 克隆仓库并编译：

```bash
# 克隆仓库
git clone https://github.com/yourusername/wsl-port-forward.git
cd wsl-port-forward

# 编译项目
cargo build --release

# 编译后的可执行文件位于 target/release/wsl-port-forward.exe
```

## 使用方法

### 基本用法

运行程序（需要管理员权限）：

```bash
# 使用默认端口（3000）
./wsl-port-forward.exe

# 指定单个端口
./wsl-port-forward.exe 8080

# 指定多个端口
./wsl-port-forward.exe 8080 3000 5000

# 指定端口范围
./wsl-port-forward.exe 8000-8010
```

### 注意事项

- 程序必须以管理员权限运行，因为需要修改网络设置和防火墙规则
- 如果端口已被占用，程序会跳过该端口
- 程序会自动清理之前设置的端口转发规则

## 工作原理

1. 获取 WSL 的 IP 地址
2. 检查管理员权限
3. 删除旧的端口代理规则
4. 为每个指定端口添加新的端口代理规则
5. 配置 Windows 防火墙规则以允许端口访问
6. 显示本地网络中可访问的 IP 地址和端口信息

## 常见问题

### 程序无法获取 WSL IP 地址

- 确保 WSL 实例已启动
- 检查 WSL 网络配置

### 端口转发失败

- 确保端口未被其他程序占用
- 检查是否以管理员权限运行程序

## 许可证

[MIT](./LICENSE)

## 贡献

欢迎提交问题和改进建议！
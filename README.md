# DomainRadar

输入一个主域名，从多个公开数据源 + DNS 暴力破解枚举其所有子域名。

## 特性

- **多源并行**：6 个独立数据源同时查询，结果聚合去重
  - `crt.sh` - Certificate Transparency 证书透明度日志
  - `HackerTarget` - hostsearch 公共 API
  - `RapidDNS` - HTML 抓取
  - `Anubis-DB` (jldc.me 镜像)
  - `AlienVault OTX` - 被动 DNS
  - `BruteForce` - 内置词典 DNS 暴力破解（可选）
- **DNS 验证**：对每个发现的子域同时查询 A / AAAA 记录，标记存活
- **三种输出**：`.txt` 全列表、`.alive.txt` 存活列表（含 IP）、`.json` 结构化结果
- **进度条 + 表格**：rich 渲染的终端 UI
- **健壮性**：单源失败不影响整体；通配符 `*.` 自动剥除；非法域名自动过滤

## 安装

```powershell
cd D:\DomainRadar
pip install -r requirements.txt
```

## 使用

### 交互模式（直接运行，按提示输入域名）

```powershell
python main.py
```

### 命令行模式

```powershell
# 仅被动源（最快，零干扰）
python main.py example.com

# 被动 + DNS 暴力破解
python main.py example.com -b

# 自定义词典 + 高并发
python main.py example.com -b -w D:\wordlists\big.txt --brute-threads 200

# 不做 DNS 解析（更快，仅列表）
python main.py example.com --no-resolve

# 只输出列表，无 UI（管道友好）
python main.py example.com -q > subs.txt
```

### 完整参数

```
domain                  目标主域名
-o, --output-dir DIR    结果输出目录（默认 ./output）
--no-passive            禁用所有被动源
-b, --bruteforce        启用 DNS 暴力破解
-w, --wordlist FILE     暴力破解词典（默认 wordlists/subdomains.txt）
--brute-threads N       暴力破解并发数（默认 80）
--no-resolve            跳过 DNS 验证
-t, --timeout SEC       DNS 超时（默认 3.0 秒）
-q, --quiet             仅输出最终列表
--no-list               只显示汇总表，不逐条列出
```

## 输出文件

每次扫描在 `output/` 下生成 3 个文件：

```
output/
  example.com.txt          # 全部唯一子域名（按层级和字典序排序）
  example.com.alive.txt    # 解析存活的子域，制表符分隔 IP
  example.com.json         # 完整结构化数据：分源结果 + 解析记录
```

## 项目结构

```
D:\DomainRadar\
├── main.py                       # CLI 入口
├── requirements.txt
├── README.md
├── wordlists\
│   └── subdomains.txt            # 内置词典（~280 项）
├── domainradar\
│   ├── __init__.py
│   ├── scanner.py                # 调度器：并行运行所有 source + 解析
│   ├── dns_resolver.py           # 多线程 DNS 解析
│   └── sources\
│       ├── __init__.py
│       ├── base.py               # BaseSource + 域名规范化/校验
│       ├── crtsh.py
│       ├── hackertarget.py
│       ├── rapiddns.py
│       ├── anubis.py
│       ├── alienvault.py
│       └── bruteforce.py
└── output\                       # 扫描结果（首次运行后填充）
```

## 合法性提醒

子域名枚举本身基于公开数据，但请仅扫描你**有授权**的目标。`-b` 暴力破解会向目标 DNS 解析路径产生大量查询，未授权的大规模扫描可能违反服务条款或当地法律。

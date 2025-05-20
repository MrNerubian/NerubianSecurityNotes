#!/bin/bash
# 增强版Nmap四扫脚本 v2.0
# 新增功能：
# 1. Web服务自动目录枚举(http-enum/gobuster) 
# 2. Web技术栈深度识别(whatweb/nikto)
# 3. NFS共享自动化检测与挂载
# 4. 结构化日志存储体系

# 错误处理函数
error_exit() {
    echo "[!] 错误: $1"
    exit 1
}

# 参数检查
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "# 用法: $0 <目标IP> <日志目录>"
  echo "# 功能: 自动化四层扫描+Web/NFS深度检测"
  exit
elif [ -z "$1" ]; then
  error_exit "必须指定目标IP和日志目录"
fi

# 初始化目录
LOG_DIR="${2:-nmap_scan_$(date +%Y%m%d%H%M)}"
mkdir -p $LOG_DIR/{web,nfs,vuln} || error_exit "无法创建日志目录"
echo "|------[ 日志存储于 $LOG_DIR ]------|"

# 功能1: 经典四层扫描
nmap_phase() {
    echo "|------[ 阶段1/4: 全端口扫描 ]------|"
    nmap -sS -Pn --min-rate 5000 -p- $1 -oN $LOG_DIR/phase1_ports.nmap
    
    NmapPorts=$(grep open $LOG_DIR/phase1_ports.nmap | awk -F'/' '{print $1}' | paste -sd ',')
    [ -z "$NmapPorts" ] && error_exit "未检测到开放端口"

    echo "|------[ 阶段2/4: 服务指纹识别 ]------|"
    nmap -sT -sV -sC -O -p$NmapPorts $1 -oN $LOG_DIR/phase2_detail.nmap -oX $LOG_DIR/phase2_detail.xml

    echo "|------[ 阶段3/4: UDP关键端口扫描 ]------|"
    nmap -sU --top-ports 30 --script=nfs-ls $1 -oN $LOG_DIR/phase3_udp.nmap

    echo "|------[ 阶段4/4: 漏洞脚本扫描 ]------|"
    nmap --script="vuln,http-*" -p$NmapPorts $1 -oN $LOG_DIR/phase4_vuln.nmap
}

# 功能2: Web深度检测
web_audit() {
    local target=$1
    echo "|------[ WEB服务深度检测启动 ]------|"
    
    # 技术栈识别
    whatweb -v -a3 http://$target https://$target > $LOG_DIR/web/whatweb_scan.txt 2>&1
    
    # 目录枚举(双引擎)
    nmap -p80,443,8080,8443 --script=http-enum $target -oN $LOG_DIR/web/nmap_http_enum.nmap
    grep -q "http-enum" $LOG_DIR/web/nmap_http_enum.nmap && \
        gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt -t 50 -o $LOG_DIR/web/gobuster_scan.txt
    
    # 漏洞扫描
    nikto -h $target -output $LOG_DIR/web/nikto_scan.html -Format html
}

# 功能3: NFS自动化检测
nfs_audit() {
    local target=$1
    echo "|------[ NFS服务检测启动 ]------|"
    
    # NFS共享枚举
    showmount -e $target > $LOG_DIR/nfs/nfs_shares.txt 2>&1
    if grep -q "Export list" $LOG_DIR/nfs/nfs_shares.txt; then
        mkdir -p /mnt/nfs_scan
        while read share; do
            mount -t nfs ${target}:${share} /mnt/nfs_scan 2>/dev/null && \
                tree /mnt/nfs_scan > $LOG_DIR/nfs/nfs_${share//\//_}.tree && \
                umount /mnt/nfs_scan
        done < <(grep -v "Export list" $LOG_DIR/nfs/nfs_shares.txt | awk '{print $1}')
    fi
}

# 主执行流程
{
    nmap_phase $1
    
    # 触发Web检测条件
    grep -qE '80/open|443/open|8080/open|8443/open' $LOG_DIR/phase1_ports.nmap && \
        web_audit $1

    # 触发NFS检测条件
    grep -qE '111/open|2049/open' $LOG_DIR/phase1_ports.nmap && \
        nfs_audit $1

    echo "|------[ 扫描完成 ]------|"
    echo "| 端口扫描: $LOG_DIR/phase1_ports.nmap"
    echo "| 服务指纹: $LOG_DIR/phase2_detail.nmap"
    echo "| Web报告: $LOG_DIR/web/{whatweb_scan,gobuster_scan,nikto_scan}"
    echo "| NFS记录: $LOG_DIR/nfs/nfs_shares.txt"
} | tee $LOG_DIR/scan_summary.log

# 生成可视化报告
xsltproc $LOG_DIR/phase2_detail.xml -o $LOG_DIR/scan_report.html 2>/dev/null
echo "| HTML报告: $LOG_DIR/scan_report.html"
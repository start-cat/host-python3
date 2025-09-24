# -*- coding: UTF-8 -*-
# Author: start-cat
# 增强版IP和域名碰撞匹配访问工具(多线程)
# 新增功能：捕获HTTP响应状态码、支持CSV格式输出、支持命令行指定线程数
import itertools
import threading
from multiprocessing.dummy import Pool as ThreadPool
from time import sleep
import argparse
import sys
import csv
import os
from datetime import datetime

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用安全警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 自定义简单进度条实现
class ProcessBar:
    def __init__(self, total):
        self.cur_cnt = 0
        self.suc_cnt = 0
        self.total = total
        self._update_display()
        
    def update(self):
        self.cur_cnt += 1
        self._update_display()
        
    def update_suc(self):
        self.suc_cnt += 1
        self._update_display()
        
    def echo(self, msg):
        # 使用标准输出，避免与进度条显示冲突
        print(f"\n{msg}")
        self._update_display()
        
    def _update_display(self):
        print(f"\r进度: {self.cur_cnt}/{self.total} | 成功: {self.suc_cnt}", end="")
        
    def close(self):
        print()  # 换行

def host_check(host_ip):
    host, ip = host_ip
    schemes = ["http://", "https://"]
    
    # 缓存局部变量以减少属性查找
    session = requests.Session()
    strip_method = host.strip
    
    for scheme in schemes:
        url = scheme + ip
        cleaned_host = strip_method()
        headers = {
            'Host': cleaned_host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = session.get(
                url, 
                verify=False, 
                headers=headers, 
                timeout=15  # 减少超时时间
            )
            
            # 获取状态码
            status_code = response.status_code
            
            # 提取标题
            title = "获取标题失败"
            try:
                # 只在响应成功时尝试获取标题
                if status_code == 200:
                    title_match = response.text[:1000]  # 只检查前1000个字符以提高性能
                    if '<title>' in title_match and '</title>' in title_match:
                        title = title_match.split('<title>')[1].split('</title>')[0][:50]
            except:
                pass
            
            # 构建结果信息
            info = f"{ip}\t{cleaned_host} -- {scheme}{cleaned_host} 状态码:{status_code} 大小：{len(response.text)} 标题：{title}"
            
            with lock:
                success_list.append(info)
                pbar.echo(info)
                pbar.update_suc()
                
                # 写入CSV文件
                with open(output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        ip, 
                        cleaned_host, 
                        scheme + cleaned_host, 
                        status_code, 
                        len(response.text), 
                        title,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ])
                    
        except Exception as e:
            error_msg = f"{ip}\t{cleaned_host} -- {scheme}{cleaned_host}  访问失败: {str(e)[:50]}"
            with lock:
                pbar.echo(error_msg)
                
                # 将错误信息也记录到CSV
                with open(output_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        ip, 
                        cleaned_host, 
                        scheme + cleaned_host, 
                        "ERROR", 
                        0, 
                        str(e)[:100],
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ])
        finally:
            pbar.update()

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="IP和域名碰撞匹配访问工具")
    parser.add_argument('-furl', '--furl', required=True, help='指定域名文件路径')
    parser.add_argument('-fip', '--fip', required=True, help='指定IP文件路径')
    parser.add_argument('-o', '--output', default='hosts_ok.csv', help='输出结果文件路径（默认为hosts_ok.csv）')
    # 新增线程数参数
    parser.add_argument('-t', '--threads', type=int, default=20, help='并发线程数（默认为20）')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()
    domain_file = args.furl
    ip_file = args.fip
    output_file = args.output
    thread_count = args.threads  # 获取用户指定的线程数
    
    lock = threading.Lock()
    success_list = []
    
    try:
        # 使用更高效的文件读取方式
        with open(ip_file, 'r', encoding='utf-8') as f:
            ip_list = [line.strip() for line in f if line.strip()]
        
        with open(domain_file, 'r', encoding='utf-8') as f:
            host_list = [line.strip() for line in f if line.strip()]
            
    except FileNotFoundError as e:
        print(f"错误：找不到文件 {e.filename}")
        sys.exit(1)
    except Exception as e:
        print(f"读取文件时出错：{e}")
        sys.exit(1)
    
    # 生成所有可能的组合
    host_ip_list = list(itertools.product(host_list, ip_list))
    total_tasks = len(host_ip_list)

    print("=" * 60)
    print(f"开始匹配 | 域名文件: {domain_file}, IP文件: {ip_file}")
    print(f"输出文件: {output_file}, 总任务数: {total_tasks}")
    print(f"并发线程数: {thread_count}")
    print("=" * 60)

    # 初始化CSV文件并写入表头
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['IP地址', '域名', '访问URL', '状态码', '响应大小', '页面标题', '检测时间'])
    
    pbar = ProcessBar(total_tasks)
    
    # 使用用户指定的线程数或默认值
    pool = ThreadPool(thread_count)

    try:
        # 直接使用map而不是map_async+循环
        pool.map(host_check, host_ip_list)
        pool.close()
        pool.join()
        
    except KeyboardInterrupt:
        print("\n用户中断执行...")
        pool.terminate()
    finally:
        pbar.close()

    print("=" * 60)
    print("匹配成功的列表:")
    for i in success_list:
        print(i)
    print("=" * 60)
    print(f"所有结果已保存到: {output_file}")

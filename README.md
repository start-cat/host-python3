# host-python3
批量检测host头碰撞漏洞，增加参数指定域名和IP文件，可指定线程数，可指定结果输出为csv文件

# 帮助
python3 host_vs_ip.py -h

# 使用默认线程数(20)
python3 host_vs_ip.py -furl domains.txt -fip ips.txt -o results.csv

# 指定使用30个线程
python3 host_vs_ip.py -furl domains.txt -fip ips.txt -o results.csv --threads 30

# 使用短参数形式指定线程数
python3 host_vs_ip.py -furl domains.txt -fip ips.txt -o results.csv -t 30


# 参考项目，进行优化
https://github.com/fofapro/Hosts_scan/tree/master

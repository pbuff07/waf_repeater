import requests
from requests.exceptions import RequestException
import time
import random
import urllib.parse
import re
from rich.table import Table
from rich.console import Console
from utils import print_error, print_info, print_success
from waf_config import get_waf_config, get_available_wafs

class WAFTester:
    def __init__(self, wafs=None, timeout=10, verify_ssl=False, user_agent=None):
        """
        初始化WAF测试器
        
        Args:
            wafs: 要测试的WAF列表，如果为None则测试所有WAF
            timeout: 请求超时时间
            verify_ssl: 是否验证SSL证书
            user_agent: 自定义User-Agent
        """
        self.wafs = wafs if wafs else get_available_wafs()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.results = []
    
    def _make_request(self, url, method="GET", data=None, headers=None):
        """发送HTTP请求并返回响应"""
        try:
            _headers = {
                "User-Agent": self.user_agent,
            }
            if headers:
                _headers.update(headers)
            
            response = requests.request(
                method=method,
                url=url,
                data=data,
                headers=_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # 检测响应内容编码
            encoding = 'utf-8'
            if 'charset=gb2312' in response.headers.get('Content-Type', '').lower() or 'charset=gb2312' in response.text.lower():
                encoding = 'gb2312'
            elif 'charset=gbk' in response.headers.get('Content-Type', '').lower() or 'charset=gbk' in response.text.lower():
                encoding = 'gbk'
            
            # 设置响应编码
            response.encoding = encoding
            
            return response
        except RequestException as e:
            print_error(f"请求失败: {url} - {str(e)}")
            return None
    
    def _is_blocked(self, response, waf_name):
        """判断请求是否被WAF拦截"""
        waf_config = get_waf_config(waf_name)
        
        # 检查响应内容中是否包含WAF拦截特征
        for signature in waf_config.get("block_signatures", []):
            if signature in response.text:
                return True
        
        return False
    
    def _extract_block_info(self, response, waf_name):
        """从拦截页面提取信息"""
            
        # 提取拦截信息的逻辑，可以根据不同WAF定制
        waf_config = get_waf_config(waf_name)
        notes = []
        
        # 使用正则表达式提取额外信息
        match_info_patterns = waf_config.get("match_info", {})
        for key, pattern in match_info_patterns.items():
            matches = re.search(pattern, response.text)
            if matches:
                # 如果有捕获组，使用第一个捕获组的内容
                if matches.groups():
                    notes.append(f"{key}: {matches.group(1)}")
        
        
        return " | ".join(notes) if notes else "None"
    
    def verify_waf_status(self):
        """自确认模式：验证WAF状态是否正常"""
        print_info("开始WAF状态自确认...")
        
        # 创建结果列表用于最终表格展示
        verify_results = []
        
        for waf_name in self.wafs:
            waf_config = get_waf_config(waf_name)
            if not waf_config:
                print_error(f"未找到WAF配置: {waf_name}")
                continue
            
            test_payload = waf_config.get("test_payload")
            if not test_payload:
                print_error(f"WAF {waf_name} 未配置测试payload")
                continue
            
            for site in waf_config.get("sites", []):
                test_url = f"{site}{test_payload}"
                print_info(f"测试 {waf_name} WAF状态: {test_url}")
                
                response = self._make_request(test_url)
                is_blocked = self._is_blocked(response, waf_name)
                
                # 收集结果
                result = {
                    "waf": waf_name,
                    "site": site,
                    "status": response is not None,
                    "blocked": is_blocked,
                    "response_code": response.status_code if response else None,
                    "notes": "WAF正常工作" if is_blocked else "WAF可能存在问题，未拦截测试payload"
                }
                verify_results.append(result)
                
                # 打印实时结果
                if is_blocked:
                    print_success(f"WAF {waf_name} 在 {site} 正常工作")
                else:
                    print_error(f"WAF {waf_name} 在 {site} 可能存在问题，未拦截测试payload")
                
                # 添加延迟，避免请求过快
                time.sleep(random.uniform(0.5, 1.5))
        
        # 使用rich库展示表格结果
        
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        
        table.add_column("WAF", style="")
        table.add_column("Site")
        table.add_column("Status", justify="center")
        table.add_column("Blocked", justify="center")
        table.add_column("Response Code", justify="center")
        table.add_column("Notes")
        
        for result in verify_results:
            status = "✅ 正常" if result["status"] else "❌ 异常"
            blocked = "🛑 已拦截" if result["blocked"] else "⚠️ 未拦截"
            
            table.add_row(
                result["waf"],
                result["site"],
                status,
                blocked,
                str(result["response_code"]) if result["response_code"] else "N/A",
                result["notes"]
            )
        
        console.print("\n[bold]WAF状态验证结果:[/bold]")
        console.print(table)
        
        # 保存结果以便可能的后续使用
        self.results = verify_results
        return verify_results
    
    def test_url_payload(self, payload):
        """测试URL中的payload"""
        print_info(f"开始测试URL payload: {payload}")
        
        for waf_name in self.wafs:
            waf_config = get_waf_config(waf_name)
            if not waf_config:
                print_error(f"未找到WAF配置: {waf_name}")
                continue
            
            for site in waf_config.get("sites", []):
                # 统一处理payload，无论是否包含协议和域名
                parsed_url = urllib.parse.urlparse(payload)
                
                # 如果包含域名部分，则只取路径和查询参数
                if parsed_url.netloc:
                    path_and_query = parsed_url.path
                    if parsed_url.query:
                        path_and_query += f"?{parsed_url.query}"
                    if parsed_url.fragment:
                        path_and_query += f"#{parsed_url.fragment}"
                    
                    # 组合WAF站点和路径
                    test_url = f"{site.rstrip('/')}{path_and_query}"
                    print_info(f"检测到域名 {parsed_url.netloc}，已替换为WAF站点")
                else:
                    # 不包含域名，可能是相对路径或者只有查询参数
                    test_url = f"{site}{payload}"
                
                print_info(f"测试 {waf_name} - {test_url}")
                
                response = self._make_request(test_url)
                is_blocked = self._is_blocked(response, waf_name)
                
                result = {
                    "waf": waf_name,
                    "site": site,
                    "status": response is not None,
                    "blocked": is_blocked,
                    "response_code": response.status_code if response else None,
                    "notes": self._extract_block_info(response, waf_name) if is_blocked else "未拦截"
                }
                
                self.results.append(result)
                
                # 添加延迟，避免请求过快
                time.sleep(random.uniform(0.5, 1.5))
        
        return self.results
    
    def get_results(self):
        """获取测试结果"""
        return self.results
    
    def clear_results(self):
        """清除测试结果"""
        self.results = []
    
    def test_request_from_file(self, request_data):
        """测试从文件加载的完整HTTP请求"""
        print_info("开始测试从文件加载的请求")
        
        # 解析HTTP请求
        lines = request_data.strip().split('\n')
        
        # 解析请求行
        request_line = lines[0].strip()
        method, path, _ = request_line.split(' ', 2)
        
        # 解析头部和正文
        headers = {}
        body = ""
        
        # 找到头部和正文的分隔点
        separator_index = -1
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                separator_index = i
                break
        
        # 解析头部
        for i in range(1, separator_index):
            if ":" in lines[i]:
                key, value = lines[i].split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 解析正文
        if separator_index > 0 and separator_index < len(lines) - 1:
            body = '\n'.join(lines[separator_index + 1:])

        # 从Host头部获取目标站点
        host = headers.get('Host', '')
        
        for waf_name in self.wafs:
            waf_config = get_waf_config(waf_name)
            if not waf_config:
                print_error(f"未找到WAF配置: {waf_name}")
                continue
            
            for site in waf_config.get("sites", []):
                # 构建完整URL
                if host:
                    # 替换原始Host为目标WAF站点
                    target_host = site.split('://')[-1].rstrip('/')
                    target_url = f"{site.split('://')[0]}://{target_host}{path}"
                    test_headers = headers.copy()
                    test_headers['Host'] = target_host
                else:
                    target_url = f"{site.rstrip('/')}{path}"
                    test_headers = headers
                print_info(f"测试 {waf_name} - {method} {target_url}")
                
                response = self._make_request(
                    url=target_url,
                    method=method,
                    data=body,
                    headers=test_headers
                )
                
                is_blocked = self._is_blocked(response, waf_name)
                
                result = {
                    "waf": waf_name,
                    "site": site,
                    "status": response is not None,
                    "blocked": is_blocked,
                    "response_code": response.status_code if response else None,
                    "notes": self._extract_block_info(response, waf_name) if is_blocked else "未拦截"
                }
                
                self.results.append(result)
                
                # 添加延迟，避免请求过快
                time.sleep(random.uniform(0.5, 1.5))
        
        return self.results
#!/usr/bin/env python3
import argparse
import sys
import urllib3
from waf_tester import WAFTester
from config.waf_config import get_available_wafs
from utils.utils import display_results, load_request_from_file, print_error, print_info, print_success

# 禁用不安全请求的警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    # 显示可用的WAF
    available_wafs = get_available_wafs()
    print_success(f"可用的WAF: {', '.join(available_wafs)}")

    parser = argparse.ArgumentParser(description="WAF Payload 拦截测试工具")
    
    # 基本参数
    parser.add_argument("--wafs", nargs="+", help="指定要测试的WAF，多个WAF用空格分隔")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间(秒)")
    parser.add_argument("--verify-ssl", action="store_true", help="验证SSL证书")
    parser.add_argument("--user-agent", help="自定义User-Agent")
    
    # 互斥模式组
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--verify", action="store_true", help="自确认模式：验证WAF状态")
    mode_group.add_argument("--url-payload", help="测试URL中的payload")
    mode_group.add_argument("--file-payload", help="从文件加载复杂请求进行测试")
    mode_group.add_argument("--cve-payload", dest="cve_id", help="指定CVE编号生成payload进行测试")
    
    args = parser.parse_args()
    
    # 初始化WAF测试器
    waf_tester = WAFTester(
        wafs=args.wafs,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,  # 直接使用参数，默认为False
        user_agent=args.user_agent
    )
    
    # 处理不同的测试模式
    if args.verify:
        # 自确认模式
        waf_tester.verify_waf_status()
    
    elif args.url_payload:
        # URL payload测试
        waf_tester.test_url_payload(args.url_payload)
    
    elif args.file_payload:
        # 复杂请求测试 - 从文件中解析所有信息
        request_data = load_request_from_file(args.file_payload)
        if request_data is None:
            print_error(f"无法加载请求文件: {args.file_payload}")
            sys.exit(1)
        
        waf_tester.test_request_from_file(request_data)
    
    elif args.cve_id:
        # CVE payload测试
        waf_tester.test_cve_payload(args.cve_id)
        return
    
    # 显示测试结果
    display_results(waf_tester.get_results())

if __name__ == "__main__":
    main()
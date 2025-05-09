#!/usr/bin/env python3
import argparse
import sys
from waf_tester import WAFTester
from utils import display_results, load_request_from_file, print_error, print_info, print_success
from waf_config import get_available_wafs

def main():
    # 显示可用的WAF
    available_wafs = get_available_wafs()
    print_success(f"可用的WAF: {', '.join(available_wafs)}")

    parser = argparse.ArgumentParser(description="WAF Payload 拦截测试工具")
    
    # 基本参数
    parser.add_argument("--wafs", nargs="+", help="指定要测试的WAF，多个WAF用空格分隔")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间(秒)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="不验证SSL证书")
    parser.add_argument("--user-agent", help="自定义User-Agent")
    
    # 互斥模式 - 三选一
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--verify", action="store_true", help="自确认模式：验证WAF状态")
    mode_group.add_argument("--url-payload", help="测试URL中的payload")
    mode_group.add_argument("--file-payload", help="从文件加载复杂请求进行测试")
    
    args = parser.parse_args()
    
    # 初始化WAF测试器
    wafs = args.wafs if args.wafs else available_wafs
    tester = WAFTester(
        wafs=wafs,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        user_agent=args.user_agent
    )
    
    # 执行测试
    if args.verify:
        # 自确认模式
        tester.verify_waf_status()
        sys.exit(0)
    
    elif args.url_payload:
        # URL payload测试
        results = tester.test_url_payload(args.url_payload)
    
    elif args.file_payload:
        # 复杂请求测试 - 从文件中解析所有信息
        request_data = load_request_from_file(args.file_payload)
        if request_data is None:
            print_error(f"无法加载请求文件: {args.file_payload}")
            sys.exit(1)
        
        results = tester.test_request_from_file(request_data)
    
    # 显示结果
    display_results(tester.get_results())

if __name__ == "__main__":
    main()
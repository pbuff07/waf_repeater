import os
import subprocess
import re
import tempfile
import platform
from config import waf_config as config
from rich.syntax import Syntax
from rich.panel import Panel
from rich.console import Console
from utils.utils import print_info, print_error, print_success

def remove_ansi_escape(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def extract_http_request(output):
    method_list = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    output = remove_ansi_escape(output)

    marker = "Dumped HTTP request for"
    marker_index = output.find(marker)
    start_pos = output.find("\n", marker_index)
    end_pos = output.find("[INF]", start_pos)
    payload_content = output[start_pos + 2:end_pos -1]

    return payload_content




def get_nuclei_path():
    """获取当前系统对应的nuclei可执行文件路径"""
    tool_config = config.get_cve_tool_config()
    
    # 根据操作系统类型选择合适的路径
    system = platform.system().lower()
    if system == "darwin":
        path_key = "path_macos"
    elif system == "windows":
        path_key = "path_windows"
    elif system == "linux":
        path_key = "path_linux"
    else:
        path_key = "path_macos"
        print_info(f"未知操作系统类型 {system}，默认使用 macOS 路径")
    
    return os.path.join(os.getcwd(), tool_config[path_key])

def search_cve_for_nuclei(cve_id):
    """使用nuclei搜索CVE并获取请求数据"""
    tool_config = config.get_cve_tool_config()
    nuclei_path = get_nuclei_path()
    templates_path = os.path.join(os.getcwd(), tool_config["templates_path"])

    # 检查nuclei是否存在
    if not os.path.exists(nuclei_path):
        print_error(f"nuclei工具不存在: {nuclei_path}")
        print_info("请确保已下载nuclei并正确配置名称后放置在正确位置（tools/目录下）")
        return None
    
    # 检查模板目录是否存在
    if not os.path.exists(templates_path):
        print_error(f"nuclei模板目录不存在: {templates_path}")
        print_info("请确保已下载nuclei-templates并放置在正确位置")
        return None
    
    # 创建临时文件用于存储输出
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
        temp_filename = temp_file.name
    
    try:
        # 构建命令
        cmd = [
            nuclei_path,
            "-id", cve_id,
            "-u", "https://www.baidu.com",
            "-t", templates_path,
            "-dreq"
        ]
        
        # 执行命令
        print_info(f"执行命令获取Payload: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        
        # 获取原始输出（二进制模式）
        output_bytes, _ = process.communicate()
        
        # 将原始输出写入临时文件
        with open(temp_filename, 'wb') as f:
            f.write(output_bytes)
            
        # 转换为文本用于处理
        output = output_bytes.decode('utf-8', errors='replace')
            
        print_info(f"nuclei输出已保存到: {temp_filename}")
        
        return output
    except Exception as e:
        print_error(f"执行nuclei时出错: {str(e)}")
        return None

def search_cve_for_others(cve_id):
    """使用其他方式搜索CVE（预留接口）"""
    print_error("目前CVE关联仅支持Nuclei模板，其他途径开发中......")
    return None

def generate_cve_payload(cve_id):
    """生成CVE相关的HTTP请求payload"""
    print_info(f"正在为CVE-{cve_id}生成测试payload...")
    
    # 首先尝试使用nuclei
    search_result = search_cve_for_nuclei(cve_id)
    
    if not search_result:
        print_error(f"无法获取CVE-{cve_id}的相关信息")
        return None
    
    # 检查nuclei是否找到模板
    if "no templates provided for scan" in search_result:
        print_error(f"Nuclei未找到CVE-{cve_id}的模板，尝试其他途径...")
        return search_cve_for_others(cve_id)
    
    # 从输出中提取HTTP请求
    http_request = extract_http_request(search_result)
    
    if http_request:
        print_success(f"成功提取CVE-{cve_id}的Payload")
        print("----------" + "\n" + http_request + "\n" + "----------")
        
        return http_request
    else:
        print_error(f"无法从nuclei输出中提取HTTP请求")
        return None
        
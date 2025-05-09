import json
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

def load_request_from_file(file_path):
    """从文件加载请求数据"""
    try:
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                return json.load(f)
            elif file_path.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f)
            else:
                return f.read()
    except Exception as e:
        console.print(f"[bold red]Error loading request file: {e}[/bold red]")
        return None

def display_results(results):
    """在终端以表格形式展示测试结果"""
    table = Table(show_header=True, header_style="bold magenta")
    
    table.add_column("WAF", style="center")
    table.add_column("Site")
    table.add_column("Status", justify="center")
    table.add_column("Blocked", justify="center")
    table.add_column("Response Code", justify="center")
    table.add_column("Notes")
    
    for result in results:
        status = "✅ 正常" if result["status"] else "❌ 异常"
        blocked = "🛑 已拦截" if result["blocked"] else "✅ 未拦截"
        
        table.add_row(
            result["waf"],
            result["site"],
            status,
            blocked,
            str(result["response_code"]),
            result["notes"]
        )
    
    console.print(table)

def print_error(message):
    """打印错误信息"""
    console.print(f"[bold red]Error: {message}[/bold red]")

def print_success(message):
    """打印成功信息"""
    console.print(f"[bold green]{message}[/bold green]")

def print_info(message):
    """打印信息"""
    console.print(f"[bold blue]{message}[/bold blue]")
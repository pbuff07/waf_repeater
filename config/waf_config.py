# WAF 配置信息

WAF_CONFIGS = {
    "创宇盾": {  # 创宇盾
        "sites": [
            "http://gac.yunaq.com/",
        ],
        "block_signatures": ["创宇盾提示您：当前访问疑似黑客攻击，已被网站管理员设置为拦截"],
        "test_payload": "/backup.mdb",  # 用于自确认模式的必拦截payload
        "match_info": {
            "rule_id": r'"rule_id":"(\d*)"'
        }
    },
    "腾讯云": {  # 腾讯云
        "sites": [
            "https://cloud.tencent.com/",
        ],
        "block_signatures": ["https://waf-static.tencent.com/501page.html"],
        "test_payload": "/?name=1%20'%20or%201=1--+",
        "match_info": {
            "id": "id=([a-z0-9-]*)&"
        }
    },
    "奇安信网站卫士": {  # 奇安信网站卫士
        "sites": [
            "https://mybase.qianxin.com/",
        ],
        "block_signatures": ["抱歉！您的访问可能对网站造成威胁，已被云防护拦截！"],
        "test_payload": "/backup.mdb",
        "match_info": {
            "id": "eventID: ([a-z0-9-.]*)</p>"
        }
    },
    "雷池WAF": {  # 雷池WAF
        "sites": [
            "https://stack.chaitin.com/",
        ],
        "block_signatures": ["安全检测能力由"],
        "test_payload": "/?filename=/etc/passwd",
    },
    "阿里云": {  # 阿里云
        "sites": [
            "https://www.aliyun.com/",
        ],
        "block_signatures": ["https://g.alicdn.com/sd/punish/waf_block.html"],
        "test_payload": "/backup.mdb",
    },
    "华为云WAF": {  # 华为云WAF
        "sites": [
            "https://www.hiascend.com/",
        ],
        "block_signatures": ["YOUR REQUEST HAS BEEN DENIED!"],
        "test_payload": "/?file=/etc/passwd",
        "match_info": {
            "id": "event_id: ([a-z0-9]*) -->"
        }
    },
    "玄武盾": {  # 玄武盾
        "sites": [
            "https://www.dbappsecurity.com.cn/",
        ],
        "block_signatures": ["https://error.websaas.cn/img/403s.png"],
        "test_payload": "/backup.mdb",
    },
    "启明星辰云WAF": {  # 启明星辰云WAF
        "sites": [
            "https://www.venustech.com.cn/",
        ],
        "block_signatures": ['onclick="onUpload()">拦截上报</a>'],
        "test_payload": "/backup.mdb",
        "match_info": {
            "id": '触发WAF防护：(.*?)<\/span>'
        }
    },
    "D盾": {  # D盾
        "sites": [
            "https://www.d99net.net/",
        ],
        "block_signatures": ["D盾_拦截提示"],
        "test_payload": "/?file=/etc/passwd",
    },
    "宝塔云WAF": {  # 宝塔云WAF
        "sites": [
            "https://www.bt.cn/",
        ],
        "block_signatures": ['"https://www.bt.cn/new/btwaf.html" target="_blank">堡塔云WAF'],
        "test_payload": "/backup.mdb",
    },
    "安全狗": {  # 安全狗
        "sites": [
            "https://www.safedog.cn/",
        ],
        "block_signatures": ["<span>如果您是网站管理员，请登录安全狗</span>"],
        "test_payload": "/?file=/etc/passwd",
    },
}

CVE_TOOLS_CONFIG = {
    "nuclei": {
        "path_macos": "tools/nuclei_macos",
        "path_windows": "tools/nuclei_windows",
        "path_linux": "tools/nuclei_linux",
        "templates_path": "tools/nuclei-templates",
    }
}

def get_available_wafs():
    """获取所有可用的WAF名称列表"""
    return list(WAF_CONFIGS.keys())

def get_waf_config(waf_name):
    """获取指定WAF的配置信息"""
    return WAF_CONFIGS.get(waf_name)

def get_cve_tool_config(tool_name="nuclei"):
    """获取CVE测试工具的配置"""
    return CVE_TOOLS_CONFIG.get(tool_name)
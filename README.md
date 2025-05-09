# WAF Payload 拦截测试器

这是一个用于测试不同 WAF (Web Application Firewall) 对 payload 拦截情况的工具。支持创宇盾、腾讯云、阿里云、玄武盾、宝塔云WAF、D盾、安全狗等多种 WAF。

## 功能特点

- 支持简单的 URL 请求验证（URL 链接中包含敏感 payload）
- 支持复杂的请求验证（POST、PUT、DELETE 等有数据包的请求）
- 支持在终端以表格形式展示测试结果
- 支持指定特定的防火墙进行验证
- 支持在防火墙拦截的情况下获取拦截页面信息
- 支持自确认模式，验证当前 WAF 的状态是否正常

## 安装

```bash
# 克隆仓库
git clone https://github.com/pbuff07/waf_repeater.git
cd waf_repeater

# 安装依赖
pip install -r requirements.txt
```

## 使用

## 自检查

```
python main.py --verify
```

自检查选项会发送对应WAF必拦截的Payload测试站点防护是否在线。

![image-20250509150613661](./images/self.png)

### 简单 URL 验证
```python
python main.py --url-payload "/?filename=/etc/passwd&content=1' union select 1,2,database(),4,5,6,7#"
```

![image-20250509150124871](./images/simple.png)

### 复杂请求验证

```python
python main.py --file-payload payload.txt
```

Payload.txt 内容如下：

```
POST //cwbase/web/themes/elfinder/php/connector.minimal.php HTTP/1.1
Host: www.baidu.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: id=4878d749336b447428d5a36114e9bfac
If-None-Match: "62efd223-3"
If-Modified-Since: Sun, 07 Aug 2022 14:54:27 GMT
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 86

target=l1_%3C@base64%3E/var/www/html/elfinder/files/%3C@/base64%3E&downLoad=1
```

![image-20250509150420604](./images/file.png)

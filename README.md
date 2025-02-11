

# 使用指南

从fofa下载对应数据

运行fofa.py进行筛选

pip install -r requirements.txt

然后运行start.sh即可



fofa 搜索参数

```
(port="65432" || port="54321") && status_code="200" && (title="登录" || title="Login") 
或者直接用fofa的fid 
fid="z2ENYvhR/6Q/agEXGFVmdA=="
```



bpb面板
```
搜索TLS站点 搜索关键词：icon_hash="-1354027319" && asn="13335" && port="443"
搜索noTLS站点 搜索关键词：icon_hash="-1354027319" && asn="13335" && port="80"

```

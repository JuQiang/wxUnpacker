# wxUnpacker
Wechat miniprogram unpacker. 微信小程序解压缩程序<br><br><br>

# 修复了网上流传工具的一些问题
### 不支持MAC上wxapkg的解密
### 无法处理加密文件
### 无法处理子包
### 无法正确生成app.json
### 无法正确生成wxml<br><br><br>

# 微信小程序文件格式
## 文件头
### 1字节 一定是190
### 4字节 一定是0
### 4字节 索引段长度
### 4字节 数据段长度
### 1字节 一定是237
### 4字节 文件总个数<br><br>

## 索引段
### 4字节 文件名长度
### N字节 文件名
### 4字节 文件在数据段中的位置（相对于header的0偏移，而不是如下数据段的0偏移）
### 4字节 文件长度
### 数据段<br><br><br>

# MAC上小程序包密钥的获得
### 1、先把mac os的SIP做一个disable or enable SIP，否则lldb不能attach到wechat进程上。
### 2、打开wechat，但是不登录。
### 3、lldb -p wechat的pid。
### 4、br set -n sqlite3_key，断点设置好后，c继续运行。
### 5、微信登录后，会break到断点上，输入memory read --size 1 --format x --count 32 $rsi
### 6、前16位即是你本机的wechat小程序加密的密钥，而完整的32位则是本机微信聊天记录sqlite db的密钥。

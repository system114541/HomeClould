HomeCloud 是一个功能丰富、注重安全与用户体验的家庭级私有云盘，基于 Node.js + Express 构建，前端采用纯静态 HTML/CSS/JavaScript，无需复杂依赖即可快速部署。以下是它的核心特点：

安装方法：

1️⃣ 环境准备
Node.js 12.x 或更高版本（推荐 LTS）
下载地址：https://nodejs.org/
npm（通常随 Node.js 一起安装）

2️⃣安装依赖
在目录下打开cmd,运行：
npm install

3️⃣ 启动服务
运行：
node server.js
或者：
npm start

如果看到：
✅ HomeCloud 服务器运行中
➜ 本地: http://localhost:8080
➜ 内网: 请查看前端显示IP
➜ 管理员: root / root (密码已哈希)
就成功了

4️⃣ 访问云盘
本地访问：http://localhost:8080
局域网访问：查看前端页面显示的 IP（如 http://192.168.1.100:8080），确保防火墙允许该端口。
首次使用：点击“创建新帐户”注册普通用户，或直接使用管理员账户 root / root（强烈建议首次登录后修改密码）。


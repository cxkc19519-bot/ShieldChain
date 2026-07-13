# Windows 本机开发原则

初版在 Windows 本机直接运行 React 前端和 FastAPI 后端，不要求安装 Docker。DeepSeek、Embedding、Reranker 和托管 Milvus 使用外部服务，本机不运行大模型或 Milvus。

具体安装和启动命令将在项目骨架创建后补充。届时必须提供：

- 支持的 Python 与 Node.js 版本。
- 安装依赖、初始化数据库、启动前后端和运行测试的命令。
- `.env.example` 及每个变量的用途，不包含真实值。
- 外部服务不可用时的模拟或降级方式。
- 数据清理、备份和常见问题排查。

后续在空间充足的电脑上提供 Docker Compose，容器配置不得成为本机开发的强制依赖。


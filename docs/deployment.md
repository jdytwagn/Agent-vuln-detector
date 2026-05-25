# 部署说明

本文档提供本地脚本部署和 Docker Compose 部署两种方式。

## 本地启动

安装依赖：

```powershell
python -m pip install -e .[model,test]
cd frontend
npm install
cd ..
```

启动：

```powershell
.\scripts\start_all.ps1
```

访问：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`

## Docker Compose 启动

```powershell
docker compose up --build
```

访问：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`

说明：

- 后端容器会挂载本地 `storage/`，用于保存 SQLite、上传文件、报告和评测结果。
- 前端容器使用 nginx 服务静态文件，并把 `/api/*` 代理到后端容器。
- `.env` 会被后端读取，但不会被复制进镜像。

## 可选 API Key 鉴权

默认不开启鉴权，方便本地演示。若要开启，在 `.env` 中增加：

```env
AGENT_DETECTOR_API_KEY=replace_with_a_strong_random_value
```

开启后：

- API 请求需要 `X-API-Key` 请求头，或 `Authorization: Bearer <key>`。
- 前端需要在构建时设置 `VITE_API_KEY`，否则无法访问受保护 API。

Docker Compose 中可以把前端构建参数改为：

```yaml
frontend:
  build:
    args:
      VITE_API_KEY: "replace_with_a_strong_random_value"
```

## 资源限制

扫描默认资源限制：

- 单次扫描最多 5000 个 C/C++ 文件。
- 单次扫描源码总大小最多 50 MB。
- 单个源码文件最多 2 MB。

CLI 可以通过以下参数调整：

```powershell
python main.py scan tests/samples --max-scan-files 10000 --max-scan-bytes 104857600 --max-file-bytes 5242880
```

API 扫描也支持 `max_scan_files`、`max_scan_bytes`、`max_file_bytes` 字段。

## 数据库迁移

当前默认数据库仍是 SQLite，但已经有 schema 版本记录和迁移入口。初始化或迁移数据库：

```powershell
python main.py migrate-db
```

指定数据库路径：

```powershell
python main.py migrate-db --db-path storage/app.db
```

也可以通过环境变量指定默认 SQLite 路径：

```env
AGENT_DETECTOR_DB_PATH=storage/app.db
```

## 生产环境仍需补充

Docker Compose 解决的是“可重复部署”和“环境固定”问题，不等于完整生产化。公网或多用户场景仍建议继续补：

- PostgreSQL 替换 SQLite，并把当前 schema 迁移表映射到正式迁移工具。
- Redis/Celery/RQ 任务队列。
- 用户登录、角色权限、项目空间隔离。
- 扫描任务取消、超时、进程隔离和并发控制。
- 结构化日志、审计日志、监控告警和报告清理策略。

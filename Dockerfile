# ---- Stage 1: Build ----
FROM node:24-alpine AS builder
WORKDIR /app

# backend
COPY server/package.json server/package-lock.json ./server/
RUN cd server && npm ci

# frontend
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- Stage 2: Runtime ----
FROM node:24-alpine
WORKDIR /app

RUN apk add --no-cache curl tini

# backend（源码 + 依赖）
COPY --from=builder /app/server ./server

# 前端构建产物（Express 直接托管静态文件，无需 vite preview + 前端 node_modules）
COPY --from=builder /app/dist ./dist

# [P0-FIX] 以非 root 用户运行：避免 RCE 后直接获得容器 root 权限
RUN addgroup -S app && adduser -S app -G app
RUN chown -R app:app /app
USER app

EXPOSE 4567

ENV NODE_ENV=production
# 容器内必须监听 0.0.0.0（否则宿主端口映射连不进来）；因此**必须配置鉴权**：
# 引擎非回环监听且无 token 时会拒绝启动（server/index.js resolveApiToken）。
# 二选一：SCAN_API_TOKEN=<强随机串> 或 SCAN_API_TOKEN_FILE=/run/secrets/scan_token
# （确知风险的隔离网络可设 SCAN_API_ALLOW_NO_TOKEN=1 恢复旧行为）
ENV HOST=0.0.0.0
ENV PORT=4567
ENV EXPLOIT_ENABLED=0
ENV ALLOWED_ORIGINS=http://localhost:4567

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -f http://127.0.0.1:4567/api/health || exit 1

# tini 作 PID1：单进程 Express 同时提供 API + 前端静态文件
# 前端产物由 Express express.static(dist) 托管，无需 vite preview
ENTRYPOINT ["tini", "--"]
CMD ["node", "/app/server/index.js"]
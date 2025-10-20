edgeone-doh
============

DoH 代理，基于请求头 `EO-Connecting-IP` 注入 EDNS Client Subnet (ECS) 并转发到上游解析器（默认 Google DoH）。支持在边缘（EdgeOne Pages Functions）与 Node 服务两种形态运行。

功能
-
- 兼容 DoH GET `/dns-query?dns=...` 与 POST `application/dns-message`
- 从 `EO-Connecting-IP` 读取客户端 IP，按 IPv4 `/24`、IPv6 `/56` 注入 ECS
- 改写 DNS 报文中的 EDNS OPT/CLIENT_SUBNET 选项（边缘版纯 Web API 实现；Node 版用 `dns-packet`）
- 默认上游 `https://dns.google/dns-query`（支持 ECS）；可通过环境变量切换

在 Edge 运行（EdgeOne Pages Functions）
-
- 入口：`functions/dns-query.js` （对应路由 `/dns-query`）与 `functions/healthz.js`
- 环境变量（通过平台配置绑定到 `env`）：
  - `UPSTREAM_DOH`：默认 `https://dns.google/dns-query`
  - `ECS_V4_PREFIX`：默认 `24`
  - `ECS_V6_PREFIX`：默认 `56`
  - `CONNECTING_IP_HEADER`：默认 `EO-Connecting-IP`
- GET 示例：

```
curl -H 'Accept: application/dns-message' \
     -H 'EO-Connecting-IP: 1.2.3.4' \
     'https://<your-edge-domain>/dns-query?dns=BASE64URL...'
```

- POST 示例：

```
curl -X POST \
     -H 'Content-Type: application/dns-message' \
     -H 'Accept: application/dns-message' \
     -H 'EO-Connecting-IP: 2001:db8::1' \
     --data-binary @query.bin \
     'https://<your-edge-domain>/dns-query'
```

本地运行（可选，Node 版）
-
- 入口：`src/server.js`
- 环境变量：`PORT`、`UPSTREAM_DOH`、`ECS_V4_PREFIX`、`ECS_V6_PREFIX`、`CONNECTING_IP_HEADER`
- 安装依赖：

```
npm i
```

- 启动：

```
npm run dev
```

- 健康检查：

```
curl http://127.0.0.1:8787/healthz
```

实现要点
-
- 边缘版：自行解析 DNS 报文头/名称压缩，定位/改写 Additional Section 中的 OPT 记录（type=41），注入/覆盖 `OPTION-CODE=8`（ECS），必要时追加新 OPT 并递增 `ARCOUNT`。
- Node 版：用 `dns-packet` 的增强编码对 `CLIENT_SUBNET` 选项进行读写。
- 始终以 POST `application/dns-message` 转发上游，避免 URL 长度限制。
- 缺少源 IP 或报文异常则透传原始报文。

注意
-
- 上游解析器对 ECS 支持不同。Google Public DNS 支持；Cloudflare 1.1.1.1 通常忽略 ECS。
- 若依赖基于用户地理的解析命中，请选择支持 ECS 的上游（如 `dns.google`）。

EdgeOne Pages Functions 文档
-
- Pages Functions 概览：https://pages.edgeone.ai/zh/document/pages-functions-overview
- Node Functions 文档：https://pages.edgeone.ai/zh/document/node-functions
- 腾讯云文档（EdgeOne Pages）：https://cloud.tencent.com/document/product/1552/118260

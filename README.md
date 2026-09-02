# Pape-Storage

面向 Pape 客户端的简易本地对象存储。服务只负责临时上传凭证、multipart 对象上传和公开对象分发，不包含账号或游戏业务。

HTTP API 使用 Gin，配置文件采用 YAML。

## 协议

- `POST /admin/v1/upload-tokens`：Pape-SDK 使用 `Authorization: Bearer <admin_token>` 获取限定对象键、有效期和体积的短期上传表单。
- `POST /`：客户端按返回的 `add_form` 发送 OSS 风格 multipart 表单，文件字段名为 `file`。
- `GET|HEAD /<object-key>`：读取对象，支持标准 `Range`、条件缓存和 HEAD 请求。
- `GET /healthz`：健康检查。

管理端请求示例：

```json
{
  "channel_id": "Photos",
  "category": "photo/a222af2f",
  "original_filename": "Upload17882734112.bin",
  "object_name": "",
  "extension": "",
  "max_bytes": 104857600
}
```

返回结构与客户端使用的阿里云 OSS 表单一致，包含 `address`、`url`、`add_form` 和 `add_header`。`x-oss-security-token` 是由 Storage 自己签发的 HMAC 短期令牌；管理员 token 不会下发给客户端。

当设备通过 Pape-SDK 的 MITM 代理联网时，建议把 `public_base_url` 设为 SDK `storage.public_host` 对应的 HTTPS 地址。SDK 会把该 Host 的上传和下载流量转发到 Storage，本地管理端路径不会公开。

## 运行

复制 `config.example.yaml` 为 `config.yaml`，替换两项独立密钥，然后执行：

```bash
go run ./cmd/pape-storage -config config.yaml
```

对象写入 `data_dir`。对象 URL 默认公开，这是为了兼容游戏客户端直接读取；写入始终要求有效临时令牌。

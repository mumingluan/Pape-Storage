# Pape-Storage

面向 Pape 客户端的本地对象存储，上传接口实现阿里云 OSS `PostObject` V4 协议。Pape-SDK
与真实阿里云 OSS、本服务使用完全相同的 policy 和签名，不再依赖 Storage 私有的令牌签发接口。

## OSS 兼容接口

- `POST /`：阿里云 OSS `PostObject`，接收 `multipart/form-data`；校验
  `OSS4-HMAC-SHA256`、Credential Scope、policy、过期时间、对象键与体积限制。
- `GET /<object-key>`：公开读取对象，支持 `Range` 与条件缓存。
- `HEAD /<object-key>`：读取对象元数据。
- `GET /healthz`：服务健康检查（扩展接口）。

上传成功响应包含 `ETag`、`Content-MD5` 和 `x-oss-request-id`；认证错误使用 OSS 风格 XML
错误响应。原有 `POST /admin/v1/upload-tokens` 已移除。

目前实现的是 Pape 客户端需要的 OSS API 子集，不包含 Bucket 管理、分片上传、版本控制等完整
OSS 服务能力。对象默认公开读取，写入必须携带有效的 V4 Post Policy。

## 配置

```yaml
bind_host: "0.0.0.0"
bind_port: 65287
data_dir: "./data/objects"
public_base_url: "https://storage-deepspace.papegames.com"

bucket: "pape"
region: "cn-hangzhou"
access_key_id: "replace-with-oss-compatible-access-key-id"
access_key_secret: "replace-with-oss-compatible-access-key-secret"
max_upload_bytes: 268435456
```

`bucket`、`region`、AccessKey 必须与 Pape-SDK 的 `storage` 配置一致。AccessKey Secret 只存在于
SDK 服务端与 Storage 服务端，不会下发给游戏客户端；客户端拿到的是限定对象键、有效期和大小的
签名 policy。

## 运行

复制 `config.example.yaml` 为 `config.yaml`，设置凭证后执行：

```bash
go run ./cmd/pape-storage -config config.yaml
```

当设备通过 Pape-SDK 的代理访问本服务时，将 SDK 的 `storage.endpoint` 指向公开域名，并将
`storage.proxy_base_url` 指向本服务的内部 HTTP 地址。接入真实阿里云 OSS 时不设置
`proxy_base_url`。

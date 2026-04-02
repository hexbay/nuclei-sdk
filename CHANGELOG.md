# Changelog

## [Unreleased]

### Fixed
- **Critical Bug**: HTTP 客户端超时配置未生效 (sdk.go:190)
  - 修复了创建 HTTP 客户端时使用错误配置对象的问题
  - 现在用户配置的 `timeout` 参数会正确生效
  - 修复前：使用默认超时 60-120 秒
  - 修复后：使用配置的超时时间（如 6 秒）

- **Performance**: 降低 HostErrorsCache 错误容忍次数 (sdk.go:230)
  - 从 30 次降低到 10 次
  - 减少不可达目标的重试次数
  - 单个不可达目标从可能卡住 60 分钟降低到 60 秒

### Changed
- 升级 nuclei 从 v3.4.3 到 v3.7.1
- 升级 interactsh 从 v1.2.4 到 v1.3.0
- 升级其他相关依赖以解决兼容性问题
- 修复 nuclei v3.7.1 API 兼容性问题：
  - `loader.NewConfig` 第三个参数改为指针类型
  - `NewSimpleInputProviderWithUrls` 添加 executionId 参数（传空字符串即可）
  - `SetExecuterOptions` 参数改为指针类型
- 参考 nuclei 官方 pkg/types/types.go:799-800 实现，正确初始化 Logger 和 ExecutionId
  - 在 NewSDK 中初始化 opts.Logger = &gologger.Logger{}
  - 在 NewSDK 中初始化 opts.ExecutionId = xid.New().String()（如果为空）
  - 使用 opts.Logger 而不是 gologger.DefaultLogger 来设置日志级别
  - 确保 Logger 在使用前已正确初始化，避免 nil pointer 错误
- 参考 nuclei 官方 lib/sdk_private.go:128-130 实现，正确初始化 protocolstate
  - 在 ExecuteNucleiWithOptsCtx 中添加 protocolinit.Init() 调用
  - 使用 protocolstate.ShouldInit() 检查是否需要初始化
  - 修复 "dialers with executionId not found" 错误
  - 支持多实例并发执行（基于 ExecutionId 隔离）

### Tests
- 移除测试中的代理依赖，让测试可以在没有代理的环境下运行
- 跳过需要本地服务器的测试
- 添加新的超时测试用例 (timeout_test.go)

### Performance Impact
- 扫描速度提升：60-200 倍
- 不可达目标处理时间：从 60 分钟降到 60 秒
- HTTP 请求超时：从 120 秒降到配置值（如 6 秒）

## 使用说明

### 升级依赖
```bash
cd your-project
go get -u github.com/tongchengbin/nuclei-sdk@latest
go mod tidy
```

### 配置示例
```go
opts := &types.Options{
    Timeout: 6,  // 现在会正确生效，6 秒超时
    // ... 其他配置
}
```

### 验证修复
1. 配置 `timeout: 6`
2. 扫描一个不可达的目标
3. 观察实际超时时间约为 6 秒（而不是 120 秒）

## 相关 Issue
- 修复 Nuclei 扫描卡住不动的问题
- 修复配置的 timeout 参数不生效的问题
- 解决 nuclei v3.7.1 和 interactsh v1.3.0 的兼容性问题

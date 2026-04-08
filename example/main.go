package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	nucleiSDK "github.com/tongchengbin/nuclei-sdk"
)

func main() {
	// 使用默认配置创建 SDK
	sdk, err := nucleiSDK.NewSDK(testutils.DefaultOptions)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}

	// 定义目标 URL
	targets := []string{"https://example.com"}

	// 执行扫描并获取结果
	results, err := sdk.ExecuteNucleiWithResult(
		context.Background(),
		targets,
		nucleiSDK.SDKOptions(func(opts *types.Options) error {
			// 配置模板路径
			opts.Templates = []string{"example/cyberpanel-rce.yaml"}
			// 可选：配置代理
			// opts.Proxy = []string{"http://127.0.0.1:10808"}
			return nil
		}),
	)

	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// 处理结果
	for _, result := range results {
		// 格式化输出结果
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal result: %v", err)
			continue
		}
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
	}

	log.Printf("Scan completed. Found %d results", len(results))
}

// 如果需要自定义回调函数处理结果
func exampleWithCallback() {
	sdk, err := nucleiSDK.NewSDK(testutils.DefaultOptions)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}

	targets := []string{"https://example.com"}

	// 使用回调函数处理每个结果
	err = sdk.ExecuteNucleiWithOptsCtx(
		context.Background(),
		targets,
		func(event *output.ResultEvent) error {
			// 实时处理每个结果
			log.Printf("[%s] %s - %s", event.Info.SeverityHolder.Severity, event.TemplateID, event.Matched)
			return nil
		},
		nucleiSDK.SDKOptions(func(opts *types.Options) error {
			opts.Templates = []string{"example/cyberpanel-rce.yaml"}
			return nil
		}),
	)

	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
}

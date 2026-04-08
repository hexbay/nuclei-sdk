package nucleiSDK

import (
	"context"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/rs/xid"
)

// NucleiSDK 它封装了 nuclei 引擎的核心功能
type NucleiSDK struct {
	ctx context.Context
	// Core components
	options       *types.Options
	templateStore map[string]*templates.Template
	// Result handling
	Callback func(*output.ResultEvent) // Executed on results
	// Thread safety
	mutex       sync.RWMutex
	safeOptions *SafeOptions
}

// SafeOptions 包含公共参数，单例模式
type SafeOptions struct {
	catalog     catalog.Catalog
	parser      *templates.Parser
	rateLimiter *ratelimit.Limiter
}
type UnsafeOptions struct {
	executeOpts protocols.ExecutorOptions
	engine      *core.Engine
}

func (u *UnsafeOptions) Close() {
	if u.executeOpts.Interactsh != nil {
		u.executeOpts.Interactsh.Close()
	}
	if u.executeOpts.Progress != nil {
		u.executeOpts.Progress.Stop()
	}
}

type SDKOptions func(opts *types.Options) error

// NewSDK 返回一个新的 NucleiSDK 实例
// 初始化所有必要的组件，包括日志级别、协议、工作池和目录
func NewSDK(opts *types.Options) (*NucleiSDK, error) {
	// 初始化 Logger（参考 nuclei 官方 pkg/types/types.go:800）
	if opts.Logger == nil {
		opts.Logger = &gologger.Logger{}
	}

	// 初始化 ExecutionId（参考 nuclei 官方 pkg/types/types.go:799）
	// 这对于 protocolstate 的正确初始化至关重要
	if opts.ExecutionId == "" {
		opts.ExecutionId = xid.New().String()
	}

	// Configure logging based on options
	if opts.Verbose {
		opts.Logger.SetMaxLevel(levels.LevelVerbose)
	} else if opts.Debug {
		opts.Logger.SetMaxLevel(levels.LevelDebug)
	} else if opts.Silent {
		opts.Logger.SetMaxLevel(levels.LevelSilent)
	}
	// fix options
	if opts.HeadlessTemplateThreads <= 0 {
		opts.HeadlessTemplateThreads = 1
	}
	ctx := context.Background()
	// 使用全局limit 可以避免多个任务同时扫描时速率、带宽控制不到位
	var rateLimiter *ratelimit.Limiter
	if opts.RateLimit > 0 {
		rateLimiter = ratelimit.New(ctx, uint(opts.RateLimit), opts.RateLimitDuration)
	} else {
		rateLimiter = ratelimit.NewUnlimited(ctx)
	}
	safeOptions := &SafeOptions{
		catalog:     disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		parser:      templates.NewParser(),
		rateLimiter: rateLimiter,
	}
	// Create SDK instance
	sdk := &NucleiSDK{
		ctx:           ctx,
		options:       opts,
		templateStore: make(map[string]*templates.Template),
		safeOptions:   safeOptions,
	}
	gologger.Debug().Msgf("Initialized NucleiSDK with options: %+v", opts)
	return sdk, nil
}

func (n *NucleiSDK) ExecuteNucleiWithResult(ctx context.Context, targets []string, opts ...SDKOptions) ([]*output.ResultEvent, error) {
	results := make([]*output.ResultEvent, 0)
	callback := func(result *output.ResultEvent) error {
		results = append(results, result)
		return nil
	}
	err := n.ExecuteNucleiWithOptsCtx(ctx, targets, callback, opts...)
	return results, err
}
func (n *NucleiSDK) ExecuteNucleiWithOptsCtx(ctx context.Context, targets []string, callback ResultCallback, opts ...SDKOptions) error {
	//	所有的初始化都需要在这里进行
	baseOpts := *n.options
	for _, opt := range opts {
		if err := opt(&baseOpts); err != nil {
			return err
		}
	}
	err := loadProxyServers(&baseOpts)
	if err != nil {
		return err
	}
	// 非线程安全 需要关闭的资源
	unsafeOpts, err := createEphemeralObjects(ctx, n.safeOptions, &baseOpts, callback)
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer unsafeOpts.Close()

	// 初始化协议状态（参考 nuclei 官方 lib/sdk_private.go:128-130）
	if protocolstate.ShouldInit(baseOpts.ExecutionId) {
		if err := protocolinit.Init(&baseOpts); err != nil {
			return errorutil.New("Could not initialize protocols: %s\n", err)
		}
	}

	// load templates
	workflowLoader, err := workflow.NewLoader(&unsafeOpts.executeOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	unsafeOpts.executeOpts.WorkflowLoader = workflowLoader
	store, err := loader.New(loader.NewConfig(&baseOpts, n.safeOptions.catalog, &unsafeOpts.executeOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	if err := store.Load(); err != nil {
		return errorutil.New("Could not load templates: %s\n", err)
	}
	inputProvider := provider.NewSimpleInputProviderWithUrls("", targets...)
	if len(store.Templates()) == 0 && len(store.Workflows()) == 0 {
		return errorutil.New("No templates available")
	}
	if inputProvider.Count() == 0 {
		return errorutil.New("No targets available")
	}
	_ = unsafeOpts.engine.ExecuteScanWithOpts(ctx, store.Templates(), inputProvider, false)
	unsafeOpts.engine.WorkPool().Wait()
	return nil
}

// createEphemeralObjects creates ephemeral nuclei objects/instances/types
func createEphemeralObjects(ctx context.Context, safeOpts *SafeOptions, opts *types.Options, callback ResultCallback) (*UnsafeOptions, error) {
	u := &UnsafeOptions{}
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	// init http client
	var httpclient *retryablehttp.Client
	var err error
	if opts.ProxyInternal && opts.AliveHttpProxy != "" || opts.AliveSocksProxy != "" {
		httpclient, err = httpclientpool.Get(opts, &httpclientpool.Configuration{})
		if err != nil {
			return nil, err
		}
	}
	if httpclient == nil {
		httpOpts := retryablehttp.DefaultOptionsSingle
		httpOpts.Timeout = 20 * time.Second // for stability reasons
		if opts.Timeout > 20 {
			httpOpts.Timeout = time.Duration(opts.Timeout) * time.Second
		} else if opts.Timeout > 0 {
			// 修复 BUG：即使 timeout <= 20 也要使用配置的值
			httpOpts.Timeout = time.Duration(opts.Timeout) * time.Second
		}
		// 修复 BUG：使用修改后的 httpOpts 而不是 DefaultOptionsSingle
		httpclient = retryablehttp.NewClient(httpOpts)
	}
	var outputWriter output.Writer
	outputWriter, err = output.NewStandardWriter(opts)
	if err != nil {
		return nil, err
	}
	if callback != nil {
		outputWriter = output.NewMultiWriter(outputWriter, NewCallOutput(callback))

	}
	interactshOpts := interactsh.DefaultOptions(outputWriter, nil, progressImpl)
	interactshOpts.HTTPClient = httpclient
	interactshClient, err := interactsh.New(interactshOpts)
	if err != nil {
		return nil, err
	}
	// todo 这里可以判断limit 是否变化、针对特定任务实现速率控制、一般情况下不需要
	u.executeOpts = protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         opts,
		Progress:        progressImpl,
		Catalog:         safeOpts.catalog,
		IssuesClient:    nil,
		RateLimiter:     safeOpts.rateLimiter,
		Interactsh:      interactshClient,
		HostErrorsCache: nil,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          safeOpts.parser,
		Browser:         nil,
		DoNotCache:      true, // 多任务环境下必须禁止缓存，不然回调无法同步
	}
	if opts.ShouldUseHostError() {
		u.executeOpts.HostErrorsCache = hosterrorscache.New(10, hosterrorscache.DefaultMaxHostsCount, nil)
	}
	u.engine = core.New(opts)
	u.engine.SetExecuterOptions(&u.executeOpts)
	return u, nil
}

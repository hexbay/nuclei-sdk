package nucleiSDK

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/rs/xid"
)

// NucleiSDK 它封装了 nuclei 引擎的核心功能
type NucleiSDK struct {
	ctx context.Context
	// Core components
	options *types.Options
	// Result handling
	Callback func(*output.ResultEvent) // Executed on results
	// Lifecycle
	mutex       sync.Mutex
	tasks       sync.WaitGroup
	closed      bool
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
	if u.executeOpts.Output != nil {
		u.executeOpts.Output.Close()
	}
	if u.executeOpts.HostErrorsCache != nil {
		u.executeOpts.HostErrorsCache.Close()
	}
	if u.executeOpts.ProjectFile != nil {
		u.executeOpts.ProjectFile.Close()
	}
	if u.executeOpts.Browser != nil {
		u.executeOpts.Browser.Close()
	}
	if u.executeOpts.InputHelper != nil {
		_ = u.executeOpts.InputHelper.Close()
	}
}

type SDKOptions func(opts *types.Options) error

var ErrSDKClosed = errors.New("nuclei SDK is closed")

// Nuclei's progress constructor updates package-level state.
var progressInitMutex sync.Mutex

// NewSDK 返回一个新的 NucleiSDK 实例
// 初始化所有必要的组件，包括日志级别、协议、工作池和目录
func NewSDK(opts *types.Options) (*NucleiSDK, error) {
	if opts == nil {
		return nil, errors.New("nuclei SDK options cannot be nil")
	}
	opts = opts.Copy()

	// 初始化 Logger（参考 nuclei 官方 pkg/types/types.go:800）
	if opts.Logger == nil {
		opts.Logger = &gologger.Logger{}
	}

	// Protocol state belongs to the SDK and is shared by all executions.
	opts.ExecutionId = xid.New().String()

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
	if err := protocolinit.Init(opts); err != nil {
		rateLimiter.Stop()
		return nil, errorutil.New("Could not initialize protocols: %s\n", err)
	}
	// Create SDK instance
	sdk := &NucleiSDK{
		ctx:         ctx,
		options:     opts,
		safeOptions: safeOptions,
	}
	gologger.Debug().Msgf("Initialized NucleiSDK with options: %+v", opts)
	return sdk, nil
}

// Close waits for active executions and releases resources owned by the SDK.
func (n *NucleiSDK) Close() error {
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return nil
	}
	n.closed = true
	n.mutex.Unlock()

	n.tasks.Wait()
	protocolinit.Close(n.options.ExecutionId)
	n.safeOptions.rateLimiter.Stop()
	return nil
}

func (n *NucleiSDK) beginExecution() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.closed {
		return ErrSDKClosed
	}
	n.tasks.Add(1)
	return nil
}

func (n *NucleiSDK) ExecuteNucleiWithResult(ctx context.Context, targets []string, opts ...SDKOptions) ([]*output.ResultEvent, error) {
	collector := newResultCollector()
	err := n.ExecuteNucleiWithOptsCtx(ctx, targets, collector.Write, opts...)
	return collector.Results(), err
}
func (n *NucleiSDK) ExecuteNucleiWithOptsCtx(ctx context.Context, targets []string, callback ResultCallback, opts ...SDKOptions) error {
	if err := n.beginExecution(); err != nil {
		return err
	}
	defer n.tasks.Done()

	//	所有的初始化都需要在这里进行
	baseOpts := n.options.Copy()
	for _, opt := range opts {
		if err := opt(baseOpts); err != nil {
			return err
		}
	}
	// Execution-scoped options cannot replace the SDK-owned protocol state.
	baseOpts.ExecutionId = n.options.ExecutionId
	err := loadProxyServers(baseOpts)
	if err != nil {
		return err
	}
	if protocolstate.ShouldInit(baseOpts.ExecutionId) {
		return errorutil.New("protocol state for SDK execution %s is not initialized\n", baseOpts.ExecutionId)
	}

	// 非线程安全 需要关闭的资源
	unsafeOpts, err := createEphemeralObjects(ctx, n.safeOptions, baseOpts, callback)
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer unsafeOpts.Close()

	// load templates
	workflowLoader, err := workflow.NewLoader(&unsafeOpts.executeOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	unsafeOpts.executeOpts.WorkflowLoader = workflowLoader
	store, err := loader.New(loader.NewConfig(baseOpts, n.safeOptions.catalog, &unsafeOpts.executeOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	if err := store.Load(); err != nil {
		return errorutil.New("Could not load templates: %s\n", err)
	}
	inputProvider := provider.NewSimpleInputProviderWithUrls(baseOpts.ExecutionId, targets...)
	defer inputProvider.Close()
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
	progressInitMutex.Lock()
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	progressInitMutex.Unlock()
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
		progressImpl.Stop()
		return nil, err
	}
	if callback != nil {
		outputWriter = output.NewMultiWriter(outputWriter, NewCallOutput(callback))

	}
	interactshOpts := interactsh.DefaultOptions(outputWriter, nil, progressImpl)
	interactshOpts.HTTPClient = httpclient
	interactshClient, err := interactsh.New(interactshOpts)
	if err != nil {
		outputWriter.Close()
		progressImpl.Stop()
		return nil, err
	}
	var projectFile *projectfile.ProjectFile
	if opts.Project || opts.ProjectPath != "" {
		projectFile, err = projectfile.New(&projectfile.Options{Path: opts.ProjectPath, Cleanup: opts.ProjectPath == ""})
		if err != nil {
			interactshClient.Close()
			outputWriter.Close()
			progressImpl.Stop()
			return nil, err
		}
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
		ProjectFile:     projectFile,
		HostErrorsCache: nil,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          safeOpts.parser,
		Browser:         nil,
		InputHelper:     input.NewHelper(),
		DoNotCache:      true,
	}
	if opts.ShouldUseHostError() {
		u.executeOpts.HostErrorsCache = hosterrorscache.New(10, hosterrorscache.DefaultMaxHostsCount, nil)
	}
	u.engine = core.New(opts)
	u.engine.SetExecuterOptions(&u.executeOpts)
	return u, nil
}

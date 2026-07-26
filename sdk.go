package nucleiSDK

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
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
	mutex              sync.Mutex
	tasks              sync.WaitGroup
	closed             bool
	safeOptions        *SafeOptions
	runtime            *UnsafeOptions
	store              *loader.Store
	templateMu         sync.Mutex
	templateSets       map[string]*templateSet
	templateTick       uint64
	cachedCount        int
	maxCachedTemplates int
	templateLoads      int
	executionSlots     chan struct{}
}

type templateSet struct {
	templates []*templates.Template
	lastUsed  uint64
}

const (
	defaultMaxConcurrentExecutions = 4
	defaultMaxCachedTemplates      = 1024
)

// RuntimeOptions bounds process-lifetime resources owned by an SDK.
type RuntimeOptions struct {
	MaxConcurrentExecutions int
	MaxCachedTemplates      int
}

// RuntimeStats reports bounded runtime state without requiring heap profiling.
type RuntimeStats struct {
	ActiveExecutions int
	CachedTemplates  int
	CachedSelections int
	TemplateLoads    int
}

// SafeOptions 包含公共参数，单例模式
type SafeOptions struct {
	catalog     catalog.Catalog
	parser      *templates.Parser
	rateLimiter *ratelimit.Limiter
}
type UnsafeOptions struct {
	executeOpts protocols.ExecutorOptions
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

// SDKOptions may select templates and adjust task scheduling. Options that
// affect protocol or template compilation must be supplied to NewSDK.
type SDKOptions func(opts *types.Options) error

var ErrSDKClosed = errors.New("nuclei SDK is closed")

// Nuclei's progress constructor updates package-level state.
var progressInitMutex sync.Mutex

// NewSDK 返回一个新的 NucleiSDK 实例
// 初始化所有必要的组件，包括日志级别、协议、工作池和目录
func NewSDK(opts *types.Options) (*NucleiSDK, error) {
	return NewSDKWithRuntimeOptions(opts, RuntimeOptions{
		MaxConcurrentExecutions: defaultMaxConcurrentExecutions,
		MaxCachedTemplates:      defaultMaxCachedTemplates,
	})
}

// NewSDKWithRuntimeOptions creates an SDK with explicit process resource limits.
func NewSDKWithRuntimeOptions(opts *types.Options, runtimeOpts RuntimeOptions) (*NucleiSDK, error) {
	if opts == nil {
		return nil, errors.New("nuclei SDK options cannot be nil")
	}
	if runtimeOpts.MaxConcurrentExecutions <= 0 {
		runtimeOpts.MaxConcurrentExecutions = defaultMaxConcurrentExecutions
	}
	if runtimeOpts.MaxCachedTemplates < 0 {
		return nil, errors.New("maximum cached templates cannot be negative")
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
	if err := loadProxyServers(opts); err != nil {
		rateLimiter.Stop()
		return nil, err
	}
	if err := protocolinit.Init(opts); err != nil {
		rateLimiter.Stop()
		return nil, errorutil.New("Could not initialize protocols: %s\n", err)
	}
	// Create SDK instance
	sdk := &NucleiSDK{
		ctx:                ctx,
		options:            opts,
		safeOptions:        safeOptions,
		templateSets:       make(map[string]*templateSet),
		executionSlots:     make(chan struct{}, runtimeOpts.MaxConcurrentExecutions),
		maxCachedTemplates: runtimeOpts.MaxCachedTemplates,
	}
	runtime, err := createSharedObjects(ctx, safeOptions, opts)
	if err != nil {
		protocolinit.Close(opts.ExecutionId)
		rateLimiter.Stop()
		return nil, err
	}
	workflowLoader, err := workflow.NewLoader(&runtime.executeOpts)
	if err != nil {
		runtime.Close()
		protocolinit.Close(opts.ExecutionId)
		rateLimiter.Stop()
		return nil, errorutil.New("Could not create workflow loader: %s\n", err)
	}
	runtime.executeOpts.WorkflowLoader = workflowLoader
	store, err := loader.New(loader.NewConfig(opts, safeOptions.catalog, &runtime.executeOpts))
	if err != nil {
		runtime.Close()
		protocolinit.Close(opts.ExecutionId)
		rateLimiter.Stop()
		return nil, errorutil.New("Could not create loader client: %s\n", err)
	}
	sdk.runtime = runtime
	sdk.store = store
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
	n.runtime.Close()
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

func (n *NucleiSDK) acquireExecution(ctx context.Context) error {
	select {
	case n.executionSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *NucleiSDK) releaseExecution() {
	<-n.executionSlots
}

// Stats returns a snapshot of SDK-owned execution and template resources.
func (n *NucleiSDK) Stats() RuntimeStats {
	n.templateMu.Lock()
	defer n.templateMu.Unlock()
	return RuntimeStats{
		ActiveExecutions: len(n.executionSlots),
		CachedTemplates:  n.cachedTemplateCount(),
		CachedSelections: len(n.templateSets),
		TemplateLoads:    n.templateLoads,
	}
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
	if err := n.acquireExecution(ctx); err != nil {
		return err
	}
	defer n.releaseExecution()

	//	所有的初始化都需要在这里进行
	baseOpts := n.options.Copy()
	for _, opt := range opts {
		if err := opt(baseOpts); err != nil {
			return err
		}
	}
	// Execution-scoped options cannot replace the SDK-owned protocol state.
	baseOpts.ExecutionId = n.options.ExecutionId
	if protocolstate.ShouldInit(baseOpts.ExecutionId) {
		return errorutil.New("protocol state for SDK execution %s is not initialized\n", baseOpts.ExecutionId)
	}
	loadedTemplates, err := n.loadTemplates(baseOpts)
	if err != nil {
		return err
	}
	inputProvider := provider.NewSimpleInputProviderWithUrls(baseOpts.ExecutionId, targets...)
	defer inputProvider.Close()
	if inputProvider.Count() == 0 {
		return errorutil.New("No targets available")
	}
	return executeTemplates(ctx, inputProvider, loadedTemplates, callback, baseOpts)
}

func (n *NucleiSDK) loadTemplates(opts *types.Options) ([]*templates.Template, error) {
	if len(opts.Workflows) > 0 || len(opts.WorkflowURLs) > 0 {
		return nil, errors.New("workflows are not supported by the shared execution path")
	}
	paths := append([]string(nil), opts.Templates...)
	paths = append(paths, opts.TemplateURLs...)
	sort.Strings(paths)

	n.templateMu.Lock()
	defer n.templateMu.Unlock()
	n.templateTick++
	if len(paths) == 0 {
		const allTemplates = "__all__"
		if cached, ok := n.templateSets[allTemplates]; ok {
			cached.lastUsed = n.templateTick
			return cached.templates, nil
		}
		loaded, err := n.store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		if err != nil {
			return nil, errorutil.New("Could not load templates: %s\n", err)
		}
		if len(loaded) == 0 {
			return nil, errorutil.New("No templates available")
		}
		n.templateLoads++
		n.cacheTemplateSet(allTemplates, loaded)
		n.purgeParserCaches()
		return loaded, nil
	}

	loaded := make([]*templates.Template, 0)
	for _, path := range paths {
		cached, ok := n.templateSets[path]
		if !ok {
			pathTemplates, err := n.store.LoadTemplates([]string{path})
			if err != nil {
				return nil, errorutil.New("Could not load templates: %s\n", err)
			}
			n.templateLoads++
			n.cacheTemplateSet(path, pathTemplates)
			n.purgeParserCaches()
			loaded = append(loaded, pathTemplates...)
			continue
		}
		cached.lastUsed = n.templateTick
		loaded = append(loaded, cached.templates...)
	}
	if len(loaded) == 0 {
		return nil, errorutil.New("No templates available")
	}
	return loaded, nil
}

func (n *NucleiSDK) cacheTemplateSet(key string, loaded []*templates.Template) {
	limit := n.maxCachedTemplates
	if limit == 0 || len(loaded) > limit {
		return
	}
	for n.cachedTemplateCount()+len(loaded) > limit {
		var oldestKey string
		var oldestTick uint64
		for candidate, entry := range n.templateSets {
			if oldestKey == "" || entry.lastUsed < oldestTick {
				oldestKey = candidate
				oldestTick = entry.lastUsed
			}
		}
		if oldestKey == "" {
			break
		}
		n.cachedCount -= len(n.templateSets[oldestKey].templates)
		delete(n.templateSets, oldestKey)
	}
	n.templateSets[key] = &templateSet{templates: loaded, lastUsed: n.templateTick}
	n.cachedCount += len(loaded)
}

func (n *NucleiSDK) cachedTemplateCount() int {
	return n.cachedCount
}

func (n *NucleiSDK) purgeParserCaches() {
	n.safeOptions.parser.Cache().Purge()
	n.safeOptions.parser.CompiledCache().Purge()
}

func executeTemplates(ctx context.Context, inputProvider *provider.SimpleInputProvider, loadedTemplates []*templates.Template, callback ResultCallback, opts *types.Options) error {
	var executionErr error
	var errorMu sync.Mutex
	var pendingMu sync.Mutex
	var pending []*output.InternalWrappedEvent

	recordError := func(err error) {
		if err == nil {
			return
		}
		errorMu.Lock()
		if executionErr == nil {
			executionErr = err
		}
		errorMu.Unlock()
	}
	onResult := func(event *output.InternalWrappedEvent) {
		event.RLock()
		results := append([]*output.ResultEvent(nil), event.Results...)
		usesInteractsh := event.UsesInteractsh
		event.RUnlock()
		if len(results) == 0 && usesInteractsh {
			pendingMu.Lock()
			pending = append(pending, event)
			pendingMu.Unlock()
			return
		}
		for _, result := range results {
			if callback != nil {
				recordError(callback(result))
			}
		}
	}

	concurrency := opts.BulkSize
	if concurrency <= 0 {
		concurrency = 1
	}
	workers := make(chan struct{}, concurrency)
	var wait sync.WaitGroup
	inputProvider.Iterate(func(target *contextargs.MetaInput) bool {
		for _, template := range loadedTemplates {
			if ctx.Err() != nil {
				recordError(ctx.Err())
				return false
			}
			workers <- struct{}{}
			wait.Add(1)
			go func(target *contextargs.MetaInput, template *templates.Template) {
				defer wait.Done()
				defer func() { <-workers }()
				if template.Executer == nil {
					recordError(errorutil.New("template %s has no executable requests", template.ID))
					return
				}
				input := contextargs.New(ctx)
				input.MetaInput = target
				scanCtx := scan.NewScanContext(ctx, input)
				scanCtx.OnResult = onResult
				if _, err := template.Executer.ExecuteWithResults(scanCtx); err != nil {
					// Protocol/request timeouts are normal no-match outcomes. Only
					// cancellation of the caller's execution context is task-fatal.
					if ctx.Err() != nil {
						recordError(ctx.Err())
					}
				}
			}(target, template)
		}
		return true
	})
	wait.Wait()

	waitForInteractsh(ctx, pending, callback, recordError, opts)
	return executionErr
}

func waitForInteractsh(ctx context.Context, pending []*output.InternalWrappedEvent, callback ResultCallback, recordError func(error), opts *types.Options) {
	if len(pending) == 0 {
		return
	}
	cooldown := time.Duration(opts.InteractionsCoolDownPeriod) * time.Second
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}
	timer := time.NewTimer(cooldown)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	remaining := append([]*output.InternalWrappedEvent(nil), pending...)
	for len(remaining) > 0 {
		select {
		case <-ctx.Done():
			recordError(ctx.Err())
			return
		case <-timer.C:
			return
		case <-ticker.C:
			next := remaining[:0]
			for _, event := range remaining {
				if !event.InteractshMatched.Load() {
					next = append(next, event)
					continue
				}
				event.RLock()
				results := append([]*output.ResultEvent(nil), event.Results...)
				event.RUnlock()
				for _, result := range results {
					if callback != nil {
						recordError(callback(result))
					}
				}
			}
			remaining = next
		}
	}
}

// createSharedObjects creates resources owned by the SDK.
func createSharedObjects(ctx context.Context, safeOpts *SafeOptions, opts *types.Options) (*UnsafeOptions, error) {
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
	return u, nil
}

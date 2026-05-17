package nucleiSDK

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/zeebo/assert"
)

// TestInteractsh 验证 SDK 能正确执行 interactsh 模板，并产出预期的扫描结果。
// 测试目的：
// 1. 加载 tests/templates/interactsh.yaml 模板。
// 2. 让本地 HTTP 服务读取模板发来的 url 头，并主动访问该 interactsh 地址。
// 3. 验证 SDK 最终能够接收到由 interactsh 回连触发的结果事件。
// 预期结果：
// 1. ExecuteNucleiWithResult 执行成功，不返回错误。
// 2. 返回结果数量大于 0。
// 3. 第一条结果的 TemplateID 为 interactsh-integration-test，说明命中的是预期模板。
func TestInteractsh(t *testing.T) {
	t.Helper()

	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)

	templatePath := filepath.Join("tests", "templates", "interactsh.yaml")

	result, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{ts.URL}, SDKOptions(func(opts *types.Options) error {
		opts.Templates = []string{templatePath}
		opts.UpdateTemplates = false
		return nil
	}))
	assert.Nil(t, err)
	assert.True(t, len(result) > 0)
	assert.Equal(t, "interactsh-integration-test", result[0].TemplateID)
}

func TestScanWithResult(t *testing.T) {
	t.Skip("Skipping test that requires local server on port 5000")
	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	results, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{"http://127.0.0.1:5000"}, SDKOptions(func(opts *types.Options) error {
		opts.Debug = true
		opts.Verbose = true
		opts.VerboseVerbose = true
		opts.Templates = []string{"test-dns.yaml"}
		return nil
	}))
	assert.Nil(t, err)
	assert.True(t, len(results) > 0)
}

func TestScanMultGlobalCallback(t *testing.T) {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	sdk, err := NewSDK(testutils.DefaultOptions)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)

	// 获取当前工作目录并构建绝对路径
	wd, _ := os.Getwd()
	templatePath := filepath.Join(wd, "tests", "templates", "interactsh.yaml")

	for i := 0; i < 3; i++ {
		results, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{ts.URL}, SDKOptions(func(opts *types.Options) error {
			opts.Templates = []string{templatePath}
			opts.UpdateTemplates = false
			return nil
		}))
		assert.Nil(t, err)
		assert.Equal(t, 1, len(results))
	}

}

// TestRateLimiterAndBulkSizeMatrix 验证 RateLimit 和 BulkSize 组合对请求到达节奏的影响。
// 测试目标：
// 1. 单次 Execute 中放入两个 target，使 BulkSize 能直接影响调度并发度。
// 2. 本地 HTTP 服务记录两个请求的到达时间，并固定等待一段时间后返回。
// 3. 通过比较两次请求的时间差，判断请求是被 BulkSize 串行、被 RateLimit 限速，还是可以并发放行。
func TestRateLimiterAndBulkSizeMatrix(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		rateLimit  int
		bulkSize   int
		minGap     time.Duration
		maxGap     time.Duration
	}{
		{
			name:      "rate_limit_2_bulk_size_1",
			rateLimit: 2,
			bulkSize:  1,
			minGap:    500 * time.Millisecond,
			maxGap:    2 * time.Second,
		},
		{
			name:      "rate_limit_1_bulk_size_2",
			rateLimit: 1,
			bulkSize:  2,
			minGap:    800 * time.Millisecond,
			maxGap:    2 * time.Second,
		},
		{
			name:      "rate_limit_2_bulk_size_2",
			rateLimit: 2,
			bulkSize:  2,
			minGap:    0,
			maxGap:    300 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sdk := newRateLimitedSDKForTest(t, tc.rateLimit, tc.bulkSize)
			getHitTimes, templatePath, targetURL := newRateLimitFixture(t, 600*time.Millisecond)

			runSingleScanWithTargets(t, sdk, templatePath, []string{targetURL + "/first", targetURL + "/second"})

			hitTimes := getHitTimes()
			assert.Equal(t, 2, len(hitTimes))
			gap := hitTimes[1].Sub(hitTimes[0])
			if gap < tc.minGap || gap > tc.maxGap {
				t.Fatalf("unexpected request gap for rate_limit=%d bulk_size=%d: gap=%s, want between %s and %s", tc.rateLimit, tc.bulkSize, gap, tc.minGap, tc.maxGap)
			}
		})
	}
}

func newRateLimitedSDKForTest(t *testing.T, rateLimit, bulkSize int) *NucleiSDK {
	t.Helper()
	baseOpts := *testutils.DefaultOptions
	baseOpts.RateLimit = rateLimit
	baseOpts.RateLimitDuration = time.Second
	baseOpts.UpdateTemplates = false
	baseOpts.Verbose = false
	baseOpts.Silent = true
	baseOpts.ProxyInternal = false
	baseOpts.InteractshURL = ""
	baseOpts.BulkSize = bulkSize
	baseOpts.TemplateThreads = 1
	baseOpts.HeadlessTemplateThreads = 1

	sdk, err := NewSDK(&baseOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sdk)
	return sdk
}

func newRateLimitFixture(t *testing.T, responseDelay time.Duration) (func() []time.Time, string, string) {
	t.Helper()

	var (
		mu   sync.Mutex
		hits []time.Time
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now())
		mu.Unlock()
		time.Sleep(responseDelay)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	templatePath := filepath.Join("tests", "templates", "ratelimit-timing.yaml")
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		result := make([]time.Time, len(hits))
		copy(result, hits)
		return result
	}, templatePath, server.URL
}

func runSingleScanWithTargets(t *testing.T, sdk *NucleiSDK, templatePath string, targets []string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := sdk.ExecuteNucleiWithResult(ctx, targets, SDKOptions(func(opts *types.Options) error {
		opts.Templates = []string{templatePath}
		opts.UpdateTemplates = false
		opts.Timeout = 5
		return nil
	}))
	assert.Nil(t, err)
}

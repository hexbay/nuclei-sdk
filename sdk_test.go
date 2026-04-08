package nucleiSDK

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/zeebo/assert"
)

func TestInteractsh(t *testing.T) {
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
	templatePath := filepath.Join(wd, "tests", "templates")

	result, err := sdk.ExecuteNucleiWithResult(context.Background(), []string{ts.URL}, SDKOptions(func(opts *types.Options) error {
		opts.Templates = []string{templatePath}
		opts.UpdateTemplates = false
		return nil
	}))
	assert.Nil(t, err)
	assert.True(t, len(result) > 0)
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

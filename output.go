package nucleiSDK

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type CallOutput struct {
	callback ResultCallback
}

func (c *CallOutput) Close() {

}

func (c *CallOutput) Colorizer() aurora.Aurora {
	return nil
}

func (c *CallOutput) Write(event *output.ResultEvent) error {
	return c.callback(event)
}

func (c *CallOutput) WriteFailure(event *output.InternalWrappedEvent) error {
	return nil
}

func (c *CallOutput) Request(templateID, url, requestType string, err error) {
}

func (c *CallOutput) RequestStatsLog(statusCode, response string) {

}

func (c *CallOutput) WriteStoreDebugData(host, templateID, eventType, data string) {

}

func (c *CallOutput) ResultCount() int {
	return 0
}

type ResultCallback func(e *output.ResultEvent) error

func NewCallOutput(callback ResultCallback) *CallOutput {
	return &CallOutput{
		callback: callback,
	}
}

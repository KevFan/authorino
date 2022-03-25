package metadata

import (
	"bytes"
	gocontext "context"
	gojson "encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
)

type GenericHttp struct {
	Endpoint     string
	Method       string
	Parameters   []json.JSONProperty
	Headers      []json.JSONProperty
	ContentType  string
	SharedSecret string
	auth.AuthCredentials
}

func (h *GenericHttp) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	if err := context.CheckContext(ctx); err != nil {
		return nil, err
	}

	authJSON := pipeline.GetAuthorizationJSON()
	endpoint := json.ReplaceJSONPlaceholders(h.Endpoint, authJSON)

	var requestBody io.Reader
	var contentType string

	method := h.Method
	switch method {
	case "GET":
		contentType = "text/plain"
		requestBody = nil
	case "POST":
		var err error
		contentType = h.ContentType
		requestBody, err = h.buildRequestBody(authJSON)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported method")
	}

	req, err := h.BuildRequestWithCredentials(ctx, endpoint, method, h.SharedSecret, requestBody)
	if err != nil {
		return nil, err
	}

	for _, header := range h.Headers {
		req.Header.Set(header.Name, fmt.Sprintf("%s", header.Value.ResolveFor(authJSON)))
	}

	req.Header.Set("Content-Type", contentType)

	if logger := log.FromContext(ctx).WithName("http").V(1); logger.Enabled() {
		logData := []interface{}{
			"method", method,
			"url", endpoint,
			"headers", req.Header,
		}
		if requestBody != nil {
			var b []byte
			_, _ = requestBody.Read(b)
			logData = append(logData, "body", string(b))
		}
		logger.Info("sending request", logData...)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response
	var claims map[string]interface{}
	err = gojson.NewDecoder(resp.Body).Decode(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (h *GenericHttp) buildRequestBody(authData string) (io.Reader, error) {
	data := make(map[string]interface{})
	for _, param := range h.Parameters {
		data[param.Name] = param.Value.ResolveFor(authData)
	}

	switch h.ContentType {
	case "application/x-www-form-urlencoded":
		formData := url.Values{}
		for key, value := range data {
			if valueAsStr, err := json.StringifyJSON(value); err != nil {
				return nil, fmt.Errorf("failed to encode http request")
			} else {
				formData.Set(key, valueAsStr)
			}
		}
		return bytes.NewBufferString(formData.Encode()), nil

	case "application/json":
		if dataJSON, err := gojson.Marshal(data); err != nil {
			return nil, err
		} else {
			return bytes.NewBuffer(dataJSON), nil
		}

	default:
		return nil, fmt.Errorf("unsupported content-type")
	}
}

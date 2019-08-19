package matcher

import (
	"encoding/json"
	"fmt"
	"github.com/duffpl/go-sip/sources"
	"github.com/pkg/errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type MatcherConfig struct {
	Type           string          `json:"type"`
	HostMatch      string          `json:"hostMatch"`
	PathMatch      string          `json:"pathMatch"`
	Source         json.RawMessage `json:"source"`
	RewritePattern string          `json:"rewritePattern"`
}

type Matcher interface {
	HasMatched(request *http.Request) bool
	GetSource() sources.DataSource
	RewritePath	(request *http.Request) (string, error)
}

var pathMatchMutex = &sync.RWMutex{}

type RequestMatcher struct {
	dataSource     sources.DataSource
	hostRegexp     *regexp.Regexp
	pathRegexp     *regexp.Regexp
	rewritePattern string
	pathMatches    map[string][]string
}


var rewriteMapRegexp *regexp.Regexp

func (m *RequestMatcher) RewritePath(request *http.Request) (string, error) {
	path := request.URL.Path
	if m.rewritePattern == "" {
		return path, nil
	}
	pathMatchMutex.RLock()
	if m.pathMatches[path] == nil {
		pathMatchMutex.RUnlock()
		return "", errors.New("no matches in path")
	}
	pathMatches := m.pathMatches[path]
	pathMatchMutex.RUnlock()
	rewriteMapMatches := rewriteMapRegexp.FindAllStringSubmatch(m.rewritePattern, -1)
	if rewriteMapMatches == nil {
		return path, nil
	}
	rewriteResult := m.rewritePattern
	for _, rewriteMatch := range rewriteMapMatches {
		rewriteIndex, _ := strconv.Atoi(rewriteMatch[1])
		if len(pathMatches) < rewriteIndex {
			return "", errors.New(fmt.Sprintf("Rewrite index '%d' out of bounds (path match count: '%d')", rewriteIndex, len(pathMatches)))
		}
		rewriteResult = strings.Replace(rewriteResult, rewriteMatch[0], pathMatches[rewriteIndex], 1)
	}
	return rewriteResult, nil
}

func (m *RequestMatcher) HasMatched(request *http.Request) (hasMatched bool) {
	if m.hostRegexp != nil && !m.hostRegexp.Match([]byte(request.Host)) {
		return false
	}
	if m.pathRegexp == nil {
		return true
	}
	path := request.URL.Path
	pathMatches := m.pathRegexp.FindStringSubmatch(path)
	pathMatchMutex.Lock()
	m.pathMatches[path] = pathMatches
	pathMatchMutex.Unlock()
	return pathMatches != nil
}

func (m *RequestMatcher) GetSource() sources.DataSource {
	return m.dataSource
}

func NewMatcher(config MatcherConfig) (matcher Matcher, err error) {
	requestMatcher := &RequestMatcher{
		pathMatches: make(map[string][]string),
	}
	if config.HostMatch != "" {
		requestMatcher.hostRegexp, err = regexp.Compile(config.HostMatch)
		if err != nil {
			return nil, errors.Wrap(err, "compiling host regexp")
		}
	}
	if config.PathMatch != "" {
		requestMatcher.pathRegexp, err = regexp.Compile(config.PathMatch)
		if err != nil {
			return nil, errors.Wrap(err, "compiling path regexp")
		}
	}
	requestMatcher.rewritePattern = config.RewritePattern
	var sourceConfig sources.DataSourceConfiguration
	err = json.Unmarshal(config.Source, &sourceConfig)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal source config")
	}
	requestMatcher.dataSource, err = sources.NewDataSource(sourceConfig)
	if err != nil {
		return nil, errors.Wrap(err, "create source")
	}
	return requestMatcher, nil
}

func init() {
	rewriteMapRegexp = regexp.MustCompile(`\$(\d+)`)
}
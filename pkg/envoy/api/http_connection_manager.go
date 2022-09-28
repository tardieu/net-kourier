/*
Copyright 2020 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package envoy

import (
	"time"

	xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	xds_matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_api_v3_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	accesslog_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	matchingv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	compositev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	stateful_sessionv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/stateful_session/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cookiev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/stateful_session/cookie/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/type/http/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"knative.dev/net-kourier/pkg/config"
)

// NewHTTPConnectionManager creates a new HttpConnectionManager that points to the given
// RouteConfig for further configuration.
func NewHTTPConnectionManager(routeConfigName string, kourierConfig *config.Kourier) *hcm.HttpConnectionManager {
	filters := make([]*hcm.HttpFilter, 0, 1)

	if config.ExternalAuthz.Enabled {
		filters = append(filters, config.ExternalAuthz.HTTPFilter)
	}

	// Append a composite filter that enables Envoy's stateful_session extension when
	// the request includes the header "Envoy-Session: cookie"
	// The session state is encapsulated in the cookie named "envoy-session"
	cookieConf, err := anypb.New(&cookiev3.CookieBasedSessionState{Cookie: &httpv3.Cookie{Name: "envoy-session"}})
	if err != nil {
		panic(err)
	}
	sessionConf, err := anypb.New(&stateful_sessionv3.StatefulSession{
		SessionState: &envoy_api_v3_core.TypedExtensionConfig{
			Name:        "envoy.http.stateful_session.cookie",
			TypedConfig: cookieConf,
		}})
	if err != nil {
		panic(err)
	}
	actionConf, err := anypb.New(&compositev3.ExecuteFilterAction{
		TypedConfig: &envoy_api_v3_core.TypedExtensionConfig{
			Name:        "envoy.filters.http.stateful_session",
			TypedConfig: sessionConf,
		}})
	if err != nil {
		panic(err)
	}
	matcherConf, err := anypb.New(&matcherv3.HttpRequestHeaderMatchInput{HeaderName: "envoy-session"})
	if err != nil {
		panic(err)
	}
	compositeConf, err := anypb.New(&matchingv3.ExtensionWithMatcher{
		XdsMatcher: &xds_matcher_v3.Matcher{
			MatcherType: &xds_matcher_v3.Matcher_MatcherTree_{
				MatcherTree: &xds_matcher_v3.Matcher_MatcherTree{
					Input: &xds_core_v3.TypedExtensionConfig{
						Name:        "matcher",
						TypedConfig: matcherConf,
					},
					TreeType: &xds_matcher_v3.Matcher_MatcherTree_ExactMatchMap{
						ExactMatchMap: &xds_matcher_v3.Matcher_MatcherTree_MatchMap{
							Map: map[string]*xds_matcher_v3.Matcher_OnMatch{
								"cookie": {
									OnMatch: &xds_matcher_v3.Matcher_OnMatch_Action{
										Action: &xds_core_v3.TypedExtensionConfig{
											Name:        "action",
											TypedConfig: actionConf,
										}}}}}}}}},
		ExtensionConfig: &envoy_api_v3_core.TypedExtensionConfig{
			Name: "envoy.filters.http.composite",
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.composite.v3.Composite",
			}}})
	if err != nil {
		panic(err)
	}
	filters = append(filters, &hcm.HttpFilter{
		Name:       "composite",
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: compositeConf},
	})

	// Append the Router filter at the end.
	filters = append(filters, &hcm.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: &anypb.Any{
			TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
		}},
	})
	enableAccessLog := kourierConfig.EnableServiceAccessLogging
	enableProxyProtocol := kourierConfig.EnableProxyProtocol
	idleTimeout := kourierConfig.IdleTimeout

	mgr := &hcm.HttpConnectionManager{
		CodecType:   hcm.HttpConnectionManager_AUTO,
		StatPrefix:  "ingress_http",
		HttpFilters: filters,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource: &envoy_api_v3_core.ConfigSource{
					ResourceApiVersion: resource.DefaultAPIVersion,
					ConfigSourceSpecifier: &envoy_api_v3_core.ConfigSource_Ads{
						Ads: &envoy_api_v3_core.AggregatedConfigSource{},
					},
					InitialFetchTimeout: durationpb.New(10 * time.Second),
				},
				RouteConfigName: routeConfigName,
			},
		},
		StreamIdleTimeout: durationpb.New(idleTimeout),
	}

	if enableProxyProtocol {
		//Force the connection manager to use the real remote address of the client connection.
		mgr.UseRemoteAddress = &wrapperspb.BoolValue{Value: true}
	}

	if enableAccessLog {
		// Write access logs to stdout by default.
		accessLog, _ := anypb.New(&accesslog_file_v3.FileAccessLog{
			Path: "/dev/stdout",
		})

		mgr.AccessLog = []*accesslog_v3.AccessLog{{
			Name: "envoy.file_access_log",
			ConfigType: &accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: accessLog,
			},
		}}
	}

	return mgr
}

// NewRouteConfig create a new RouteConfiguration with the given name and hosts.
func NewRouteConfig(name string, virtualHosts []*route.VirtualHost) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// Without this validation we can generate routes that point to non-existing clusters
		// That causes some "no_cluster" errors in Envoy and the "TestUpdate"
		// in the Knative serving test suite fails sometimes.
		// Ref: https://github.com/knative/serving/blob/f6da03e5dfed78593c4f239c3c7d67c5d7c55267/test/conformance/ingress/update_test.go#L37
		ValidateClusters: wrapperspb.Bool(true),
	}
}

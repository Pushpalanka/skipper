package opaauthorizerequest

import (
	"fmt"
	opasdktest "github.com/open-policy-agent/opa/sdk/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/builtin"
	"github.com/zalando/skipper/filters/openpolicyagent"
	"github.com/zalando/skipper/proxy/proxytest"
	"github.com/zalando/skipper/tracing/tracingtest"
	"net/http"
	"testing"
)

func TestOpaRouteUpdates(t *testing.T) {
	bs := startBundleServer("bundle1")
	defer bs.Stop()

	cases := []struct {
		name         string
		initial      []*eskip.Route
		update       []*eskip.Route
		deleteIDs    []string
		expectRoutes []string
	}{
		{
			name:         "add OPA route",
			initial:      []*eskip.Route{},
			update:       eskip.MustParse(`r1: Path("/initial") -> opaAuthorizeRequest("bundle1", "") -> status(204) -> <shunt>`),
			expectRoutes: []string{"r1"},
		},
		//{
		//	name:         "delete OPA route",
		//	initial:      eskip.MustParse(`r1: Path("/initial") -> opaAuthorizeRequest("bundle1", "") -> status(204) -> <shunt>`),
		//	update:       []*eskip.Route{},
		//	deleteIDs:    []string{"r1"},
		//	expectRoutes: []string{},
		//},
		//{
		//	name:         "add a route with invalid OPA bundle",
		//	initial:      eskip.MustParse(`r1: Path("/initial") -> status(204) -> <shunt>`),
		//	update:       eskip.MustParse(`r2: Path("/update") -> opaAuthorizeRequest("invalid-bundle", "") -> status(204) -> <shunt>`),
		//	expectRoutes: []string{"r1"},
		//},
	}

	fr := createFilterRegistry(bs.URL())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tproxy := proxytest.New(fr, tc.initial...)
			//editor := eskip.NewEditor(
			//	regexp.MustCompile(`opaAuthorizeRequest\("invalid-bundle", ""\)`),
			//	`status(403)`,
			//)
			//
			//tproxy := proxytest.WithParamsAndRoutingOptions(fr,
			//	proxy.Params{
			//		AccessLogDisabled: true,
			//	},
			//	routing.Options{
			//		PreProcessors: []routing.PreProcessor{
			//			routing.PreProcessor(editor),
			//		},
			//	},
			//	tc.initial...)

			err := tproxy.UpdateRoutes(tc.update, tc.deleteIDs)
			assert.NoError(t, err)

			routes := tproxy.GetRoutes()
			var gotIDs []string
			for id := range routes {
				gotIDs = append(gotIDs, id)
			}
			assert.ElementsMatch(t, tc.expectRoutes, gotIDs)
			for _, deletedID := range tc.deleteIDs {
				assert.NotContains(t, gotIDs, deletedID, "route %s should have been deleted", deletedID)
			}
			req, err := http.NewRequest("GET", tproxy.URL+"/initial", nil)
			rsp, err := tproxy.Client().Do(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusNoContent, rsp.StatusCode)

			tproxy.Close()
		})
	}
}

func createFilterRegistry(url string) filters.Registry {
	fr := make(filters.Registry)

	config := []byte(fmt.Sprintf(`{
				"services": {
					"test": {
						"url": %q
					}
				},
				"bundles": {
					"test": {
						"resource": "/bundles/{{ .bundlename }}"
					}
				},
				"labels": {
					"environment": "test"
				},
				"plugins": {
					"envoy_ext_authz_grpc": {
						"path": "envoy/authz/allow",
						"dry-run": false
					}
				}
			}`, url))

	envoyMetaDataConfig := []byte(`{
				"filter_metadata": {
					"envoy.filters.http.header_to_metadata": {
						"policy_type": "ingress"
					}
				}
			}`)

	opts := make([]func(*openpolicyagent.OpenPolicyAgentInstanceConfig) error, 0)
	opts = append(opts,
		openpolicyagent.WithConfigTemplate(config),
		openpolicyagent.WithEnvoyMetadataBytes(envoyMetaDataConfig))

	//toDO control loop configuration to control retrying
	opaFactory := openpolicyagent.NewOpenPolicyAgentRegistry(openpolicyagent.WithTracer(tracingtest.NewTracer()))
	ftSpec := NewOpaAuthorizeRequestSpec(opaFactory, opts...)
	fr.Register(ftSpec)
	fr.Register(builtin.NewStatus())

	return fr

}

func startBundleServer(bundleName string) *opasdktest.Server {
	return opasdktest.MustNewServer(
		opasdktest.MockBundle(fmt.Sprintf("/bundles/%s", bundleName), map[string]string{
			"main.rego": `
						package envoy.authz
						import rego.v1

						default allow := true

						allow if {
							input.parsed_path == [ "initial" ]
						}
						`,
		}),
	)

}

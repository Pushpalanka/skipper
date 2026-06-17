package opaserveresponse

// TestRealBundleActivationProfile measures activation cost for supplier-auth using the
// exact production bundles downloaded fresh from the prod S3 bucket.
//
// This is the production-faithful benchmark that validates the findings from the synthetic
// 2×2 factorial test (TestNestingVsSplitActivationCost). It uses OpaServeResponse — the
// same filter used in production — with real Rego, real data, and production polling config.
//
// # Bundle layout
//
//	real_bundles_supplier/
//	  v1/
//	    policy.tgz          ← V1 combined policy bundle (80 Rego files)
//	    context-data.tgz    ← V1 context-data (27 data.json files, dir-tree, depth≈5)
//	  v2/
//	    main.tgz            ← V2 policy bundle (59 Rego files)
//	    suppliers__context-data.tgz     ← V2 supplier data (1 data.json, depth≈9.2)
//	    global_authentication__context-data.tgz
//	    global_authorization__context-data.tgz
//	    baseline__context-data.tgz
//
// # Metrics
//
//   - heap-delta  = retained heap after two post-GC passes (steady-state memory)
//   - peak-delta  = max HeapInuse during activation minus pre-activation baseline
//                   (baseline-corrected so accumulated process allocations cancel out)
//   - total-alloc = cumulative bytes allocated (transient GC pressure indicator)
//   - gc-cycles   = GC cycles triggered during activation
//
// # Polling config
//
// min_delay_seconds=10, max_delay_seconds=120 — matching the production OCP default
// so the test exercises the same polling frequency that caused the production spike.
//
// # Run
//
//	go test -v -count=1 -run TestRealBundleActivationProfile -timeout 120s \
//	  ./filters/openpolicyagent/opaserveresponse/
//
// # Capture pprof profiles (run each sub-test in isolation)
//
//	go test -v -count=1 -run TestRealBundleActivationProfile/V1 \
//	  -memprofile=../../../../../../performance-migration/real_bundles_supplier/v1_mem.out \
//	  -cpuprofile=../../../../../../performance-migration/real_bundles_supplier/v1_cpu.out \
//	  -timeout 120s ./filters/openpolicyagent/opaserveresponse/
//
//	go test -v -count=1 -run TestRealBundleActivationProfile/V2 \
//	  -memprofile=../../../../../../performance-migration/real_bundles_supplier/v2_mem.out \
//	  -cpuprofile=../../../../../../performance-migration/real_bundles_supplier/v2_cpu.out \
//	  -timeout 120s ./filters/openpolicyagent/opaserveresponse/

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	opatestutils "github.com/zalando/skipper/filters/openpolicyagent/internal/opatestutils"
)

func TestRealBundleActivationProfile(t *testing.T) {
	const root = "../../../../../performance-migration/real_bundles_supplier/"

	type bundleScenario struct {
		name        string
		bundleFiles map[string]string
		// polling mirrors production OCP config: min=10s, max=120s
		bundlePolling map[string]opatestutils.BundlePollingConfig
	}

	prodPolling := func(names ...string) map[string]opatestutils.BundlePollingConfig {
		m := make(map[string]opatestutils.BundlePollingConfig, len(names))
		for _, n := range names {
			m[n] = opatestutils.BundlePollingConfig{MinDelaySeconds: 10, MaxDelaySeconds: 120}
		}
		return m
	}

	scenarios := []bundleScenario{
		{
			// V1 (Styra DAS): 2 bundles.
			// policy.tgz: 80 Rego files (all libraries bundled inline).
			// context-data.tgz: 27 data.json files in dir-tree format, avg depth 5.0.
			// Total data: 437k nodes, 162k leaves.
			name: "V1_supplier_auth",
			bundleFiles: map[string]string{
				"main":         root + "v1/policy.tgz",
				"context-data": root + "v1/context-data.tgz",
			},
			bundlePolling: prodPolling("context-data"),
		},
		{
			// V2 (OCP): 5 bundles.
			// main.tgz: 59 Rego files (global libraries now in separate bundles).
			// suppliers__context-data.tgz: 1 data.json, depth 9.2 — the V2 structural change.
			// + 3 shared library bundles (global_authentication, global_authorization, baseline).
			// Total data: 447k nodes, 167k leaves across all 4 context bundles.
			name: "V2_supplier_auth",
			bundleFiles: map[string]string{
				"main":                    root + "v2/main.tgz",
				"suppliers__context-data": root + "v2/suppliers__context-data.tgz",
				"global_authentication":   root + "v2/global_authentication__context-data.tgz",
				"global_authorization":    root + "v2/global_authorization__context-data.tgz",
				"baseline":                root + "v2/baseline__context-data.tgz",
			},
			bundlePolling: prodPolling(
				"suppliers__context-data",
				"global_authentication",
				"global_authorization",
				"baseline",
			),
		},
	}

	type result struct {
		nBundles     int
		heapDeltaMB  float64
		peakDeltaMB  float64
		totalAllocMB float64
		gcCycles     uint32
		elapsed      time.Duration
	}
	results := make(map[string]result)

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			// Skip gracefully if bundles are not present.
			for name, path := range sc.bundleFiles {
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Skipf("bundle %q not found at %s — run download first", name, path)
				}
			}

			server := opatestutils.NewBundleServerFromFiles(t, sc.bundleFiles)
			defer server.Close()

			bundleNames := opatestutils.BundleNamesFrom(sc.bundleFiles)

			// Log bundle sizes for transparency.
			for name, path := range sc.bundleFiles {
				info, _ := os.Stat(path)
				if info != nil {
					t.Logf("  bundle %-40s  %d KB", name, info.Size()/1024)
				}
			}

			// Two GC passes to evict any allocations from prior sub-tests.
			runtime.GC()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			// Background sampler: peak HeapInuse at 1 ms intervals.
			// GC runs completely naturally — nothing is disabled.
			// peakAbsBytes initialised at before.HeapInuse so the delta is zero-based.
			var peakAbsBytes uint64
			atomic.StoreUint64(&peakAbsBytes, before.HeapInuse)
			var samplerDone uint32
			go func() {
				var m runtime.MemStats
				for atomic.LoadUint32(&samplerDone) == 0 {
					runtime.ReadMemStats(&m)
					for {
						old := atomic.LoadUint64(&peakAbsBytes)
						if m.HeapInuse <= old {
							break
						}
						if atomic.CompareAndSwapUint64(&peakAbsBytes, old, m.HeapInuse) {
							break
						}
					}
					time.Sleep(1 * time.Millisecond)
				}
			}()

			start := time.Now()
			_, err := createOpaServeResponseFilter(FilterOptions{
				OpaControlPlaneUrl:  server.URL,
				DecisionConsumerUrl: server.URL,
				DecisionPath:        benchDecisionPath, // "main/main"
				BundleNames:         bundleNames,
				BundlePolling:       sc.bundlePolling,
			})
			elapsed := time.Since(start)
			atomic.StoreUint32(&samplerDone, 1)
			require.NoError(t, err)

			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&after)

			peakDeltaMB := float64(int64(atomic.LoadUint64(&peakAbsBytes))-int64(before.HeapInuse)) / 1024 / 1024
			heapDeltaMB := float64(int64(after.HeapInuse)-int64(before.HeapInuse)) / 1024 / 1024
			totalAllocMB := float64(after.TotalAlloc-before.TotalAlloc) / 1024 / 1024
			gcCycles := after.NumGC - before.NumGC

			results[sc.name] = result{
				nBundles:     len(sc.bundleFiles),
				heapDeltaMB:  heapDeltaMB,
				peakDeltaMB:  peakDeltaMB,
				totalAllocMB: totalAllocMB,
				gcCycles:     gcCycles,
				elapsed:      elapsed,
			}

			t.Logf("bundles: %d   activation: %s   heap-delta: %.1f MB   peak-delta: %.1f MB   total-alloc: %.1f MB   gc-cycles: %d",
				len(sc.bundleFiles),
				elapsed.Round(time.Millisecond),
				heapDeltaMB, peakDeltaMB, totalAllocMB, gcCycles,
			)
		})
	}

	v1, v1ok := results["V1_supplier_auth"]
	v2, v2ok := results["V2_supplier_auth"]
	if !v1ok || !v2ok {
		return
	}

	t.Logf("")
	t.Logf("=== REAL PRODUCTION BUNDLE COMPARISON: supplier-auth V1 vs V2 ===")
	t.Logf("  Production polling: min_delay=10s, max_delay=120s (OCP default)")
	t.Logf("")
	t.Logf("  %-14s  bundles: %d  heap-delta: %5.1f MB  peak-delta: %5.1f MB  total-alloc: %5.1f MB  time: %s",
		"V1 (Styra DAS):", v1.nBundles, v1.heapDeltaMB, v1.peakDeltaMB, v1.totalAllocMB, v1.elapsed.Round(time.Millisecond))
	t.Logf("  %-14s  bundles: %d  heap-delta: %5.1f MB  peak-delta: %5.1f MB  total-alloc: %5.1f MB  time: %s",
		"V2 (OCP):", v2.nBundles, v2.heapDeltaMB, v2.peakDeltaMB, v2.totalAllocMB, v2.elapsed.Round(time.Millisecond))
	t.Logf("")
	t.Logf("  V1→V2 delta:")
	t.Logf("    heap-delta  : %+.1f MB  (retained memory — nesting drives more map[string]interface{} nodes in store)", v2.heapDeltaMB-v1.heapDeltaMB)
	t.Logf("    peak-delta  : %+.1f MB  (activation peak — nesting + compiler working sets)", v2.peakDeltaMB-v1.peakDeltaMB)
	t.Logf("    total-alloc : %+.1f MB  (transient GC pressure — more nodes + extra compiler.Compile passes)", v2.totalAllocMB-v1.totalAllocMB)
	t.Logf("    time        : %+s", (v2.elapsed - v1.elapsed).Round(time.Millisecond))
	t.Logf("    bundles     : %+d  (3 extra compiler.Compile(59 modules) runs)", v2.nBundles-v1.nBundles)
}

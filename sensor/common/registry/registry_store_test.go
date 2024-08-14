package registry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/docker/config"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/registries"
	"github.com/stackrox/rox/pkg/registries/types"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/sensor/common/registry/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fakeImgName = &storage.ImageName{
		Registry: "example.com",
		Remote:   "rhacs-eng/sandbox",
		Tag:      "noexist",
		FullName: "example.com/rhacs-eng/sandbox:noexist",
	}

	fakeNamespace     = "fake-namespace"
	fakeSecretName    = "fake-secret-name"
	noServiceAcctName = ""
	bgCtx             = context.Background()
)

// alwaysInsecureCheckTLS is an implementation of registry.CheckTLS
// which always says the given address is insecure.
func alwaysInsecureCheckTLS(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func alwaysSecureCheckTLS(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func alwaysFailCheckTLS(_ context.Context, _ string) (bool, error) {
	return false, errors.New("fake tls failure")
}

func TestRegistryStore_SameNamespace(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		sameNamespaceSubTest(t)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		sameNamespaceSubTest(t)
	})
}

func sameNamespaceSubTest(t *testing.T) {
	regStore := NewRegistryStore(alwaysInsecureCheckTLS)

	dce := config.DockerConfigEntry{Username: "username", Password: "password"}

	dc := config.DockerConfig{
		"image-registry.openshift-image-registry.svc:5000":       dce,
		"image-registry.openshift-image-registry.svc.local:5000": dce,
		"172.99.12.11:5000": dce,
	}

	regStore.UpsertSecret("qa", fakeSecretName, dc, noServiceAcctName)

	img := &storage.ImageName{
		Registry: "image-registry.openshift-image-registry.svc:5000",
		Remote:   "qa/nginx",
		Tag:      "nginx:1.18.0",
		FullName: "image-registry.openshift-image-registry.svc:5000/qa/nginx:1.18.0",
	}
	regs, err := regStore.GetPullSecretRegistries(img, "qa", nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, img.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)

	img = &storage.ImageName{
		Registry: "image-registry.openshift-image-registry.svc.local:5000",
		Remote:   "qa/nginx",
		Tag:      "nginx:1.18.0",
		FullName: "image-registry.openshift-image-registry.svc.local:5000/qa/nginx:1.18.0",
	}

	regs, err = regStore.GetPullSecretRegistries(img, "qa", nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, img.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)

	img = &storage.ImageName{
		Registry: "172.99.12.11:5000",
		Remote:   "qa/nginx",
		Tag:      "nginx:1.18.0",
		FullName: "172.99.12.11:5000/qa/nginx:1.18.0",
	}
	regs, err = regStore.GetPullSecretRegistries(img, "qa", nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, img.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)
}

// TestRegistryStore_SpecificNamespace tests interactions with the registry store
// using an explicitly provided namespace (vs. inferred)
func TestRegistryStore_SpecificNamespace(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		regStore := specificNamespaceSubTest(t)

		// no registry should exist based on img.Remote
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, "qa", nil)
		assert.Error(t, err)
		assert.Empty(t, regs)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		regStore := specificNamespaceSubTest(t)

		// no registry should exist based on img.Remote
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, "qa", nil)
		assert.NoError(t, err)
		assert.Empty(t, regs)
	})
}

func specificNamespaceSubTest(t *testing.T) *Store {
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dc := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	regStore := NewRegistryStore(alwaysInsecureCheckTLS)
	regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
	regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, fakeImgName.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)
	assert.Equal(t, "username", regs[0].Config(bgCtx).Username)

	return regStore
}

// TestRegistryStore_MultipleSecretsSameRegistry tests that upsert overwrites
// registry entries with matching endpoints when storing secrets by host
// instead of name.
func TestRegistryStore_MultipleSecretsSameRegistry(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		multipleSecretsSameRegistrySubTest(t)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		multipleSecretsSameRegistrySubTest(t)
	})
}

func multipleSecretsSameRegistrySubTest(t *testing.T) {
	regStore := NewRegistryStore(alwaysInsecureCheckTLS)
	dceA := config.DockerConfigEntry{Username: "usernameA", Password: "passwordA"}
	dceB := config.DockerConfigEntry{Username: "usernameB", Password: "passwordB"}
	dcA := config.DockerConfig{fakeImgName.GetRegistry(): dceA}
	dcB := config.DockerConfig{fakeImgName.GetRegistry(): dceB}

	regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcA, "")
	regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, fakeImgName.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)
	assert.Equal(t, dceA.Username, regs[0].Config(bgCtx).Username)
	assert.Equal(t, dceA.Password, regs[0].Config(bgCtx).Password)

	regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcB, "")
	regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, nil)
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, fakeImgName.GetRegistry(), regs[0].Config(bgCtx).RegistryHostname)
	assert.Equal(t, dceB.Username, regs[0].Config(bgCtx).Username)
	assert.Equal(t, dceB.Password, regs[0].Config(bgCtx).Password)
}

func TestRegistryStore_LazyNoFailUpsertCheckTLS(t *testing.T) {
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dc := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		regStore := NewRegistryStore(alwaysFailCheckTLS)

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
		regs := regStore.storeByHost[fakeNamespace]
		allRegs := regs.GetAll()
		require.Len(t, allRegs, 1)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		regStore := NewRegistryStore(alwaysFailCheckTLS)

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
		secs := regStore.storeByName[fakeNamespace]
		require.Len(t, secs, 1)

		hostToRegistry := secs[fakeSecretName]
		require.Len(t, hostToRegistry, 1)
	})
}

func TestRegistryStore_GlobalStore(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		regStore := globalStoreSubTest(t)

		assert.Zero(t, len(regStore.storeByHost), "non-global store should not have been modified")
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		regStore := globalStoreSubTest(t)

		assert.Len(t, regStore.storeByName, 1, "non-global store should have also had an upsert")
	})
}

func globalStoreSubTest(t *testing.T) *Store {
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dc := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	regStore := NewRegistryStore(alwaysInsecureCheckTLS)

	_, err := regStore.GetGlobalRegistry(fakeImgName)
	require.Error(t, err, "error is expected on empty store")

	regStore.UpsertSecret(openshiftConfigNamespace, openshiftConfigPullSecret, dc, "")
	reg, err := regStore.GetGlobalRegistry(fakeImgName)
	require.NoError(t, err, "should be no error on valid get")
	assert.NotNil(t, reg)
	assert.Equal(t, reg.Config(bgCtx).Username, dce.Username)

	return regStore
}

func TestRegistryStore_GlobalStoreLazyNoFailUpsertCheckTLS(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		globalStoreLazyNoFailUpsertCheckTLSSubTests(t)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		globalStoreLazyNoFailUpsertCheckTLSSubTests(t)
	})
}

func globalStoreLazyNoFailUpsertCheckTLSSubTests(t *testing.T) {
	regStore := NewRegistryStore(alwaysFailCheckTLS)
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dc := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	// Upsert should NOT fail on lazy TLS check
	regStore.UpsertSecret(openshiftConfigNamespace, openshiftConfigPullSecret, dc, "")
	require.False(t, regStore.globalRegistries.IsEmpty())
	allRegs := regStore.globalRegistries.GetAll()
	require.Len(t, allRegs, 1)
}

func TestRegistryStore_CentralIntegrations(t *testing.T) {
	regStore := NewRegistryStore(alwaysFailCheckTLS)

	iis := []*storage.ImageIntegration{
		{Id: "bad", Name: "bad", Type: "bad"},
		{Id: "a", Name: "a", Type: types.DockerType, IntegrationConfig: &storage.ImageIntegration_Docker{}},
		{Id: "b", Name: "b", Type: types.DockerType, IntegrationConfig: &storage.ImageIntegration_Docker{}},
		{Id: "c", Name: "c", Type: types.DockerType, IntegrationConfig: &storage.ImageIntegration_Docker{
			Docker: &storage.DockerConfig{Endpoint: "example.com"}},
		},
	}

	regStore.UpsertCentralRegistryIntegrations(iis)
	assert.Len(t, regStore.centralRegistryIntegrations.GetAll(), 3)

	regStore.DeleteCentralRegistryIntegrations([]string{"a", "b"})
	assert.Len(t, regStore.centralRegistryIntegrations.GetAll(), 1)

	imgName, _, err := utils.GenerateImageNameFromString("example.com/repo/path:tag")
	require.NoError(t, err)
	regs := regStore.GetCentralRegistries(imgName)
	assert.Len(t, regs, 1)
}

func TestRegistryStore_CreateImageIntegrationType(t *testing.T) {
	ii := createImageIntegration("http://example.com", config.DockerConfigEntry{}, "")
	assert.Equal(t, ii.Type, types.DockerType)

	ii = createImageIntegration("https://registry.redhat.io", config.DockerConfigEntry{}, "")
	assert.Equal(t, ii.Type, types.RedHatType)
}

func TestRegistryStore_IsLocal(t *testing.T) {
	regStore := NewRegistryStore(alwaysInsecureCheckTLS)
	regStore.addClusterLocalRegistryHost("image-registry.openshift-image-registry.svc:5000")

	specificRegs := []*central.DelegatedRegistryConfig_DelegatedRegistry{
		{Path: "isfound.svc/repo/path"},
		{Path: "otherfound.svc"},
	}

	tt := map[string]struct {
		image    *storage.ImageName
		config   *central.DelegatedRegistryConfig
		expected bool
	}{
		"nil": {
			image:    nil,
			config:   nil,
			expected: false,
		},
		"cluster local": {
			image: &storage.ImageName{
				Registry: "image-registry.openshift-image-registry.svc:5000",
			},
			config:   nil,
			expected: true,
		},
		"nil config": {
			image: &storage.ImageName{
				Registry: "noexist.svc",
			},
			config:   nil,
			expected: false,
		},
		"enabled for none": {
			image: &storage.ImageName{
				Registry: "noexist.svc",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_NONE,
			},
			expected: false,
		},
		"enabled for all": {
			image: &storage.ImageName{
				Registry: "noexist.svc",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_ALL,
			},
			expected: true,
		},
		"specific not found": {
			image: &storage.ImageName{
				Registry: "isnotfound.svc",
				FullName: "isnotfound.svc/repo/path",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_SPECIFIC,
				Registries: specificRegs,
			},
			expected: false,
		},
		"specific found by host": {
			image: &storage.ImageName{
				Registry: "otherfound.svc",
				FullName: "otherfound.svc/random/path",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_SPECIFIC,
				Registries: specificRegs,
			},
			expected: true,
		},
		"specific found by path": {
			image: &storage.ImageName{
				Registry: "isfound.svc",
				FullName: "isfound.svc/repo/path",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_SPECIFIC,
				Registries: specificRegs,
			},
			expected: true,
		},
		"specific not found by path": {
			image: &storage.ImageName{
				Registry: "isfound.svc",
				FullName: "isfound.svc/notfound/repo/path",
			},
			config: &central.DelegatedRegistryConfig{
				EnabledFor: central.DelegatedRegistryConfig_SPECIFIC,
				Registries: specificRegs,
			},
			expected: false,
		},
	}

	for name, test := range tt {
		tf := func(t *testing.T) {
			regStore.SetDelegatedRegistryConfig(test.config)
			r := regStore.IsLocal(test.image)

			assert.Equal(t, test.expected, r)
		}

		t.Run(name, tf)
	}
}

func TestRegistryStore_GenImgIntName(t *testing.T) {
	tt := []struct {
		prefix    string
		namespace string
		name      string
		registry  string
		expected  string
	}{
		{"", "", "", "", ""},
		{"PRE", "", "", "", "PRE"},
		{"PRE", "", "", "REG", "PRE/reg:REG"},
		{"PRE", "NAMESP", "", "", "PRE/ns:NAMESP"},
		{"PRE", "NAMESP", "", "REG", "PRE/ns:NAMESP/reg:REG"},
		{"PRE", "", "NAME", "", "PRE/name:NAME"},
		{"PRE", "NAMESP", "NAME", "", "PRE/ns:NAMESP/name:NAME"},
		{"PRE", "NAMESP", "NAME", "REG", "PRE/ns:NAMESP/name:NAME/reg:REG"},
	}

	for i, test := range tt {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			actual := genIntegrationName(test.prefix, test.namespace, test.name, test.registry)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDataRaceAtCleanup(t *testing.T) {
	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		dataRaceAtCleanupSubTest()
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		dataRaceAtCleanupSubTest()
	})
}

func dataRaceAtCleanupSubTest() {
	regStore := NewRegistryStore(alwaysInsecureCheckTLS)
	regStore.storeByHost[fakeNamespace] = registries.NewSet(regStore.factory)
	wg := sync.WaitGroup{}
	doneSignal := concurrency.NewSignal()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-doneSignal.Done():
				return
			default:
				// random reads
				_, _ = regStore.GetPullSecretRegistries(&storage.ImageName{}, fakeNamespace, nil)
				regStore.getRegistries(fakeNamespace)
				regStore.IsLocal(&storage.ImageName{})
				regStore.GetCentralRegistries(&storage.ImageName{})
				_, _ = regStore.GetGlobalRegistry(&storage.ImageName{})
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	regStore.Cleanup()
	doneSignal.Signal()
	wg.Wait()
}

// TestRegistryStore_UpsertsByServiceAccount ensures that secrets
// are upserted as expected based on associated service account names
func TestRegistryStore_UpsertsByServiceAccount(t *testing.T) {
	imagePullSecrets := []string{"sec1", "sec2", "sec3"}
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dcA := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	imgB, _, err := utils.GenerateImageNameFromString("reg.internal/repo/path:tag")
	require.NoError(t, err)
	dcB := config.DockerConfig{imgB.GetRegistry(): dce}

	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)

		// With delegated scanning disabled only secrets associated with the default
		// service account should be upserted.
		t.Setenv(env.DelegatedScanningDisabled.EnvVar(), "true")

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[0], dcA, "fake-name") // skipped
		_, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.Error(t, err)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[1], dcA, "") // skipped
		_, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.Error(t, err)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[2], dcA, defaultSA) // upserted
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		// With delegated scanning enabled secrets associated with the default
		// service account or no service account should be upserted. Secrets
		// from any other service account should NOT be upserted
		t.Setenv(env.DelegatedScanningDisabled.EnvVar(), "false")

		regStore = NewRegistryStore(alwaysInsecureCheckTLS)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[0], dcA, "fake-name") // skipped
		_, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.Error(t, err)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[1], dcA, "") // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[2], dcB, defaultSA) // upserted
		regs, err = regStore.GetPullSecretRegistries(imgB, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		// sanity check - ensure two different registries were inserted into the store
		assert.Len(t, regStore.getRegistriesInNamespace(fakeNamespace).GetAll(), 2)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)

		// With delegated scanning disabled secrets associated with any service
		// account should be upserted. Secrets not associated with a service
		// account should NOT be upserted.
		t.Setenv(env.DelegatedScanningDisabled.EnvVar(), "true")

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[0], dcA, "") // skipped
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 0)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[1], dcA, "fake-name") // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[2], dcA, defaultSA) // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 2)

		// With Delegated scanning enabled all secrets should be upserted.
		t.Setenv(env.DelegatedScanningDisabled.EnvVar(), "false")

		regStore = NewRegistryStore(alwaysInsecureCheckTLS)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[0], dcA, "") // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[1], dcA, "fake-name") // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 2)

		regStore.UpsertSecret(fakeNamespace, imagePullSecrets[2], dcA, defaultSA) // upserted
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 3)
	})
}

// TestRegistryStore_SecretDelete ensures that secrets are deleted (or not deleted)
// as expected.
func TestRegistryStore_SecretDelete(t *testing.T) {
	imagePullSecrets := []string{fakeSecretName, "sec1", "sec2"}
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dcA := config.DockerConfig{fakeImgName.GetRegistry(): dce}

	t.Run("SecretsByHost", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)

		assert.False(t, regStore.DeleteSecret(fakeNamespace, fakeSecretName), "no deletes should occur when storing by host")

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcA, "")
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		assert.False(t, regStore.DeleteSecret(fakeNamespace, fakeSecretName), "no deletes should occur when storing by host")

		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)
	})

	t.Run("SecretsByName", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)

		assert.False(t, regStore.DeleteSecret(fakeNamespace, fakeSecretName), "should have been nothing to delete")

		regStore.UpsertSecret(fakeNamespace, "sec1", dcA, "")
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		regStore.UpsertSecret(fakeNamespace, "sec2", dcA, "")
		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 2)

		assert.False(t, regStore.DeleteSecret(fakeNamespace, "noexist"), "should return false when secret doesn't exist")
		assert.True(t, regStore.DeleteSecret(fakeNamespace, "sec1"), "should have been a secret deleted")
		assert.NotNil(t, regStore.storeByName[fakeNamespace])

		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 1)

		assert.True(t, regStore.DeleteSecret(fakeNamespace, "sec2"), "should have been a secret deleted")
		assert.Nil(t, regStore.storeByName[fakeNamespace])

		regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
		require.NoError(t, err)
		assert.Len(t, regs, 0)
	})
}

// TestRegistryStore_GetPullSecretRegistries ensures that the correct
// registries are returned given a set of pull secrets (or no pull secrets)
func TestRegistryStore_GetPullSecretRegistries(t *testing.T) {
	testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)

	regStore := NewRegistryStore(alwaysInsecureCheckTLS)

	imagePullSecrets := []string{"secB", "secA"}
	dceA := config.DockerConfigEntry{Username: "usernameA", Password: "passwordA"}
	dceB := config.DockerConfigEntry{Username: "usernameB", Password: "passwordB"}
	dcA := config.DockerConfig{fakeImgName.GetRegistry(): dceA}
	dcB := config.DockerConfig{fakeImgName.GetRegistry(): dceB}

	regStore.UpsertSecret(fakeNamespace, "secA", dcA, "")
	regStore.UpsertSecret(fakeNamespace, "secB", dcB, "")

	regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, imagePullSecrets)
	require.NoError(t, err)
	assert.Len(t, regs, 2)
	assert.Equal(t, "passwordB", regs[0].Config(bgCtx).Password)
	assert.Equal(t, "passwordA", regs[1].Config(bgCtx).Password)

	regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, []string{"secA"})
	require.NoError(t, err)
	assert.Len(t, regs, 1)
	assert.Equal(t, "passwordA", regs[0].Config(bgCtx).Password)

	regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, []string{"secB"})
	require.NoError(t, err)
	assert.Len(t, regs, 1)
	assert.Equal(t, "passwordB", regs[0].Config(bgCtx).Password)

	regs, err = regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, nil)
	require.NoError(t, err)
	assert.Len(t, regs, 2)
	assert.Equal(t, "passwordA", regs[0].Config(bgCtx).Password)
	assert.Equal(t, "passwordB", regs[1].Config(bgCtx).Password)
}

func TestRegistyStore_Metrics(t *testing.T) {
	dce := config.DockerConfigEntry{Username: "username", Password: "password"}
	dc := config.DockerConfig{"example.com": dce}
	dcTwo := config.DockerConfig{"example.com": dce, "example.net": dce}

	t.Run("global registries count", func(t *testing.T) {
		c := metrics.GlobalSecretEntriesCount
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(openshiftConfigNamespace, openshiftConfigPullSecret, dc, "")
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		// repeat with same input, gauge should NOT increase
		regStore.UpsertSecret(openshiftConfigNamespace, openshiftConfigPullSecret, dc, "")
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(openshiftConfigNamespace, openshiftConfigPullSecret, dcTwo, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("cluster local host count", func(t *testing.T) {
		c := metrics.ClusterLocalHostsCount
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, defaultSA)
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		// repeat with same input, gauge should NOT increase
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, defaultSA)
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, defaultSA)
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("central integration count", func(t *testing.T) {
		c := metrics.CentralIntegrationsCount
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		iis := []*storage.ImageIntegration{
			createImageIntegration("http://example.com/1", config.DockerConfigEntry{}, ""),
			createImageIntegration("http://example.com/2", config.DockerConfigEntry{}, ""),
		}
		regStore.UpsertCentralRegistryIntegrations(iis)
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Repeat with same input, gauge should NOT increase.
		regStore.UpsertCentralRegistryIntegrations(iis)
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		regStore.DeleteCentralRegistryIntegrations([]string{"http://example.com/1"})
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("SecretsByHost: pull secret count", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		c := metrics.PullSecretEntriesCount
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Repeat with same input, gauge should NOT increase.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Repeat with one less entry but still an existing entry, gauge should NOT change.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Delete secret should do nothing when secrets are stored by host.
		regStore.DeleteSecret(fakeNamespace, fakeSecretName)
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("SecretsByHost: pull secret size", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, false)
		c := metrics.PullSecretEntriesSize
		metrics.ResetRegistryMetrics()

		name := genIntegrationName(pullSecretNamePrefix, fakeNamespace, "", "example.com")
		entrySize := float64(createImageIntegration("example.com", dce, name).SizeVT())

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		// Repeat with same input, gauge should NOT increase.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		// Repeat with one less entry but still an existing entry, gauge should NOT change.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		// Delete secret should do nothing when secrets are stored by host.
		regStore.DeleteSecret(fakeNamespace, fakeSecretName)
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("SecretsByName: pull secret count", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		c := metrics.PullSecretEntriesCount
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Repeat with same input, gauge should NOT increase.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, 2.0, testutil.ToFloat64(c))

		// Add a new secret with single entry, gauge SHOULD increase.
		regStore.UpsertSecret(fakeNamespace, "fake-thingy-name", dc, "")
		assert.Equal(t, 3.0, testutil.ToFloat64(c))

		regStore.DeleteSecret(fakeNamespace, fakeSecretName)
		assert.Equal(t, 1.0, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("SecretsByName: pull secret size", func(t *testing.T) {
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		c := metrics.PullSecretEntriesSize
		metrics.ResetRegistryMetrics()

		name := genIntegrationName(pullSecretNamePrefix, fakeNamespace, fakeSecretName, "example.com")
		entrySize := float64(createImageIntegration("example.com", dce, name).SizeVT())
		t.Logf("entrySize: %v", entrySize)

		regStore := NewRegistryStore(alwaysInsecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		// Repeat with same input, gauge should NOT increase.
		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dcTwo, "")
		assert.Equal(t, entrySize*2, testutil.ToFloat64(c))

		// Add a new secret with single entry, gauge SHOULD increase.
		regStore.UpsertSecret(fakeNamespace, "fake-thingy-name", dc, "")
		assert.Equal(t, entrySize*3, testutil.ToFloat64(c))

		// Update an existing secret with larger size entry, gauge should increase by diff.
		dceNew := config.DockerConfigEntry{
			Username: dce.Username + "123", // add 3 bytes
			Password: dce.Password,
		}
		dcNew := config.DockerConfig{"example.com": dceNew}

		regStore.UpsertSecret(fakeNamespace, "fake-thingy-name", dcNew, "")
		assert.Equal(t, (entrySize*3)+3, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, "fake-thingy-name", dc, "")
		assert.Equal(t, entrySize*3, testutil.ToFloat64(c))

		regStore.DeleteSecret(fakeNamespace, fakeSecretName)
		assert.Equal(t, entrySize, testutil.ToFloat64(c))

		regStore.Cleanup()
		assert.Equal(t, 0.0, testutil.ToFloat64(c))
	})

	t.Run("No crash on negative gauge", func(t *testing.T) {
		// The size in bytes of an image integration is calculated when it is inserted into
		// the store. It's possible that the integration changes internally after insertion.
		// When the integration is deleted its size may be different creating a skew in the
		// size metric. This should be OK as the number of bytes is only a rough estimate and
		// not the actual amount of 'memory consumed'. The byte count should still be
		// 'statistically' relevant and provide a meaningful relative size for comparison.
		// This test ensures that if the gauge goes into a 'negative value' nothing will break.
		testutils.MustUpdateFeature(t, features.SensorPullSecretsByName, true)
		c := metrics.PullSecretEntriesSize
		metrics.ResetRegistryMetrics()

		regStore := NewRegistryStore(alwaysSecureCheckTLS)
		assert.Equal(t, 0.0, testutil.ToFloat64(c))

		regStore.UpsertSecret(fakeNamespace, fakeSecretName, dc, "")
		regs, err := regStore.GetPullSecretRegistries(fakeImgName, fakeNamespace, nil)
		require.NoError(t, err)
		require.Len(t, regs, 1)

		ii := regs[0].Source()
		ii.Name = ii.Name + "1234567890" // Add 10 'bytes' to the integration name

		regStore.DeleteSecret(fakeNamespace, fakeSecretName)
		assert.Equal(t, -10.0, testutil.ToFloat64(c))
	})
}

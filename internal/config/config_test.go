// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	objects      = "-\n  secretPath: \"v1/secret/foo1\"\n  objectName: \"bar1\"\n  filePermission: 0600"
	certsSPCYaml = `apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: openbao-foo
spec:
  provider: openbao
  parameters:
    objects: |
      - objectName: "test-certs"
        secretPath: "pki/issue/example-dot-com"
        secretKey: "certificate"
        secretArgs:
          common_name: "test.example.com"
          ip_sans: "127.0.0.1"
          exclude_cn_from_sans: true
        method: "PUT"
      - objectName: "internal-certs"
        secretPath: "pki/issue/example-dot-com"
        secretArgs:
          common_name: "internal.example.com"
        method: "PUT"
`
)

func TestParseParametersFromYaml(t *testing.T) {
	// Test starts with a minimal simulation of the processing the driver does
	// with each SecretProviderClass yaml.
	var secretProviderClass struct {
		Spec struct {
			Parameters map[string]string `yaml:"parameters"`
		} `yaml:"spec"`
	}
	err := yaml.Unmarshal([]byte(certsSPCYaml), &secretProviderClass)
	require.NoError(t, err)
	paramsBytes, err := json.Marshal(secretProviderClass.Spec.Parameters)
	require.NoError(t, err)

	// This is now the form the provider receives the data in.
	params, err := parseParameters(string(paramsBytes))
	require.NoError(t, err)

	require.Equal(t, Parameters{
		Secrets: []Secret{
			{
				ObjectName: "test-certs",
				SecretPath: "pki/issue/example-dot-com",
				SecretKey:  "certificate",
				SecretArgs: map[string]interface{}{
					"common_name":          "test.example.com",
					"ip_sans":              "127.0.0.1",
					"exclude_cn_from_sans": true,
				},
				Method: "PUT",
			},
			{
				ObjectName: "internal-certs",
				SecretPath: "pki/issue/example-dot-com",
				SecretArgs: map[string]interface{}{
					"common_name": "internal.example.com",
				},
				Method: "PUT",
			},
		},
	}, params)
}

func TestParseParameters(t *testing.T) {
	// This file's contents are copied directly from a driver mount request.
	parametersStr, err := os.ReadFile(filepath.Join("testdata", "example-parameters-string.txt"))
	require.NoError(t, err)
	actual, err := parseParameters(string(parametersStr))
	require.NoError(t, err)
	expected := Parameters{
		OpenbaoRoleName: "example-role",
		OpenbaoAddress:  "http://openbao:8200",
		OpenbaoTLSConfig: api.TLSConfig{
			Insecure: true,
		},
		Secrets: []Secret{
			{"bar1", "v1/secret/foo1", "", http.MethodGet, nil, 0, ""},
			{"bar2", "v1/secret/foo2", "", "", nil, 0, ""},
		},
		PodInfo: PodInfo{
			Name:               "nginx-secrets-store-inline",
			UID:                "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:          "test",
			ServiceAccountName: "default",
		},
		Audience: "testaudience",
	}
	require.Equal(t, expected, actual)
}

func TestParseConfig(t *testing.T) {
	const roleName = "example-role"
	const targetPath = "/some/path"
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
		expected   Config
	}{
		{
			name:       "defaults",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":         "example-role",
				"baoSkipTLSVerify": "true",
				"objects":          objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := Parameters{}
					expected.OpenbaoRoleName = roleName
					expected.OpenbaoTLSConfig.Insecure = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					}
					return expected
				}(),
			},
		},
		{
			name:       "set all options",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":                                 "example-role",
				"baoSkipTLSVerify":                         "true",
				"baoAddress":                               "my-openbao-address",
				"baoNamespace":                             "my-openbao-namespace",
				"baoKubernetesMountPath":                   "my-mount-path",
				"baoCACertPath":                            "my-ca-cert-path",
				"baoCADirectory":                           "my-ca-directory",
				"baoTLSServerName":                         "mytls-server-name",
				"baoTLSClientCertPath":                     "my-tls-client-cert-path",
				"baoTLSClientKeyPath":                      "my-tls-client-key-path",
				"csi.storage.k8s.io/pod.name":              "my-pod-name",
				"csi.storage.k8s.io/pod.uid":               "my-pod-uid",
				"csi.storage.k8s.io/pod.namespace":         "my-pod-namespace",
				"csi.storage.k8s.io/serviceAccount.name":   "my-pod-sa-name",
				"csi.storage.k8s.io/serviceAccount.tokens": `{"my-aud": {"token": "my-pod-sa-token", "expirationTimestamp": "bar"}, "other-aud": {"token": "unused-token"}}`,
				"objects":                                  objects,
				"audience":                                 "my-aud",
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoRoleName:      roleName,
					OpenbaoAddress:       "my-openbao-address",
					OpenbaoNamespace:     "my-openbao-namespace",
					OpenbaoAuthMountPath: "my-mount-path",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
					OpenbaoTLSConfig: api.TLSConfig{
						CACert:        "my-ca-cert-path",
						CAPath:        "my-ca-directory",
						ClientCert:    "my-tls-client-cert-path",
						ClientKey:     "my-tls-client-key-path",
						TLSServerName: "mytls-server-name",
						Insecure:      true,
					},
					PodInfo: PodInfo{
						"my-pod-name",
						"my-pod-uid",
						"my-pod-namespace",
						"my-pod-sa-name",
						"my-pod-sa-token",
					},
					Audience: "my-aud",
				},
			},
		},
		{
			name:       "backwards compatibility to openbao prefix for parameters",
			targetPath: targetPath,
			parameters: map[string]string{
				"openbaoRoleName":            "example-role",
				"openbaoSkipTLSVerify":       "true",
				"openbaoAddress":             "my-openbao-address",
				"openbaoNamespace":           "my-openbao-namespace",
				"openbaoKubernetesMountPath": "my-mount-path",
				"openbaoCACertPath":          "my-ca-cert-path",
				"openbaoCADirectory":         "my-ca-directory",
				"openbaoTLSServerName":       "mytls-server-name",
				"openbaoTLSClientCertPath":   "my-tls-client-cert-path",
				"openbaoTLSClientKeyPath":    "my-tls-client-key-path",
				"objects":                    objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoRoleName:      roleName,
					OpenbaoAddress:       "my-openbao-address",
					OpenbaoNamespace:     "my-openbao-namespace",
					OpenbaoAuthMountPath: "my-mount-path",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
					OpenbaoTLSConfig: api.TLSConfig{
						CACert:        "my-ca-cert-path",
						CAPath:        "my-ca-directory",
						ClientCert:    "my-tls-client-cert-path",
						ClientKey:     "my-tls-client-key-path",
						TLSServerName: "mytls-server-name",
						Insecure:      true,
					},
				},
			},
		},
		{
			name:       "backwards compatibility to vault prefix for parameters",
			targetPath: targetPath,
			parameters: map[string]string{
				"vaultRoleName":            "example-role",
				"vaultSkipTLSVerify":       "true",
				"vaultAddress":             "my-openbao-address",
				"vaultNamespace":           "my-openbao-namespace",
				"vaultKubernetesMountPath": "my-mount-path",
				"vaultCACertPath":          "my-ca-cert-path",
				"vaultCADirectory":         "my-ca-directory",
				"vaultTLSServerName":       "mytls-server-name",
				"vaultTLSClientCertPath":   "my-tls-client-cert-path",
				"vaultTLSClientKeyPath":    "my-tls-client-key-path",
				"objects":                  objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoRoleName:      roleName,
					OpenbaoAddress:       "my-openbao-address",
					OpenbaoNamespace:     "my-openbao-namespace",
					OpenbaoAuthMountPath: "my-mount-path",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
					OpenbaoTLSConfig: api.TLSConfig{
						CACert:        "my-ca-cert-path",
						CAPath:        "my-ca-directory",
						ClientCert:    "my-tls-client-cert-path",
						ClientKey:     "my-tls-client-key-path",
						TLSServerName: "mytls-server-name",
						Insecure:      true,
					},
				},
			},
		},
		{
			name:       "check precedence of new parameters over old - when all three have the same value",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":       "example-role",
				"vaultAddress":   "my-openbao-address",
				"baoAddress":     "my-openbao-address",
				"openbaoAddress": "my-openbao-address",
				"objects":        objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoAddress:  "my-openbao-address",
					OpenbaoRoleName: "example-role",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
				},
			},
		},
		{
			name:       "check precedence of new parameters over old - bao before all",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":       "example-role",
				"vaultAddress":   "my-wrong-address",
				"baoAddress":     "my-openbao-address",
				"openbaoAddress": "my-also-wrong-address",
				"objects":        objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoAddress:  "my-openbao-address",
					OpenbaoRoleName: "example-role",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
				},
			},
		},
		{
			name:       "check precedence of new parameters over old - bao > vault",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":     "example-role",
				"vaultAddress": "my-wrong-address",
				"baoAddress":   "my-openbao-address",
				"objects":      objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoAddress:  "my-openbao-address",
					OpenbaoRoleName: "example-role",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
				},
			},
		},
		{
			name:       "check precedence of new parameters over old - bao > openbao",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":       "example-role",
				"openbaoAddress": "my-openbao-address",
				"baoAddress":     "my-openbao-address",
				"objects":        objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoAddress:  "my-openbao-address",
					OpenbaoRoleName: "example-role",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
				},
			},
		},
		{
			name:       "check precedence of new parameters over old - openbao > vault",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":       "example-role",
				"openbaoAddress": "my-openbao-address",
				"vaultAddress":   "my-wrong-address",
				"objects":        objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					OpenbaoAddress:  "my-openbao-address",
					OpenbaoRoleName: "example-role",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					},
				},
			},
		},
	} {
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		cfg, err := Parse(string(parametersStr), tc.targetPath, "420")
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.expected, cfg)
	}
}

func TestParseConfig_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		name       string
		targetPath string
		parameters map[string]string
	}{
		"no roleName": {
			parameters: map[string]string{
				"baoSkipTLSVerify": "true",
				"objects":          objects,
			},
		},
		"no secrets configured": {
			parameters: map[string]string{
				"roleName":         "example-role",
				"baoSkipTLSVerify": "true",
				"objects":          "",
			},
		},
		"both baoAuthMountPath and baoKubernetesMountPath specified": {
			parameters: map[string]string{
				"roleName":               "example-role",
				"baoSkipTLSVerify":       "true",
				"baoAuthMountPath":       "foo",
				"baoKubernetesMountPath": "bar",
				"objects":                objects,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			parametersStr, err := json.Marshal(tc.parameters)
			require.NoError(t, err)
			_, err = Parse(string(parametersStr), "/some/path", "420")
			require.Error(t, err, tc.name)
		})
	}
}

func TestValidateConfig(t *testing.T) {
	minimumValid := Config{
		TargetPath: "a",
		Parameters: Parameters{
			OpenbaoAddress:  "http://127.0.0.1:8200",
			OpenbaoRoleName: "b",
			Secrets:         []Secret{{}},
		},
	}
	for _, tc := range []struct {
		name     string
		cfg      Config
		cfgValid bool
	}{
		{
			name:     "minimum valid",
			cfgValid: true,
			cfg:      minimumValid,
		},
		{
			name: "No role name",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Parameters.OpenbaoRoleName = ""
				return cfg
			}(),
		},
		{
			name: "No target path",
			cfg: func() Config {
				cfg := minimumValid
				cfg.TargetPath = ""
				return cfg
			}(),
		},
		{
			name: "No secrets configured",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Parameters.Secrets = []Secret{}
				return cfg
			}(),
		},
		{
			name: "Duplicate objectName",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Parameters.Secrets = []Secret{
					{ObjectName: "foo", SecretPath: "path/one"},
					{ObjectName: "foo", SecretPath: "path/two"},
				}
				return cfg
			}(),
		},
	} {
		err := tc.cfg.validate()
		if tc.cfgValid {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
		}
	}
}

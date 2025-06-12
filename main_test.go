// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-hclog"

	"github.com/stretchr/testify/require"
)

func TestListen(t *testing.T) {
	logger := hclog.NewNullLogger()
	dir, err := os.MkdirTemp("/tmp", "TestListen")
	require.NoError(t, err)
	endpoint := path.Join(dir, "openbao.sock")
	defer func() {
		require.NoError(t, os.Remove(endpoint))
	}()

	// Works when no file in the way.
	l, err := listen(logger, endpoint)
	require.NoError(t, err)

	// Will replace existing file.
	require.NoError(t, l.Close())
	_, err = os.Create(endpoint)
	require.NoError(t, err)
}

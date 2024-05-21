// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientcache

import (
	"sync"

	"github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru/v2"
	openbaoclient "github.com/openbao/openbao-csi-provider/internal/client"
	"github.com/openbao/openbao-csi-provider/internal/config"
)

type ClientCache struct {
	logger hclog.Logger

	mtx   sync.Mutex
	cache *lru.Cache[cacheKey, *openbaoclient.Client]
}

// NewClientCache intializes a new client cache. The cache's lifetime
// should be tied to the provider process (i.e. longer than a single
// mount request) so that Openbao tokens stored in the clients are cached
// and reused across different mount requests for the same pod.
func NewClientCache(logger hclog.Logger, size int) (*ClientCache, error) {
	var cache *lru.Cache[cacheKey, *openbaoclient.Client]
	var err error
	if size > 0 {
		logger.Info("Creating Openbao client cache", "size", size)
		cache, err = lru.New[cacheKey, *openbaoclient.Client](size)
		if err != nil {
			return nil, err
		}
	} else {
		logger.Info("Disabling Openbao client cache", "size", size)
	}

	return &ClientCache{
		logger: logger,
		cache:  cache,
	}, nil
}

func (c *ClientCache) GetOrCreateClient(params config.Parameters, flagsConfig config.FlagsConfig) (*openbaoclient.Client, error) {
	if c.cache == nil {
		return openbaoclient.New(c.logger, params, flagsConfig)
	}

	key, err := makeCacheKey(params)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if cachedClient, ok := c.cache.Get(key); ok {
		return cachedClient, nil
	}

	client, err := openbaoclient.New(c.logger, params, flagsConfig)
	if err != nil {
		return nil, err
	}

	c.cache.Add(key, client)
	return client, nil
}

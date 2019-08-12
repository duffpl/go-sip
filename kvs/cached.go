package kvs

type Cached struct {
	cacheKVS KVS
	sourceKVS KVS
}

func (c Cached) Get(key string) (data []byte, err error) {

	data, err = c.cacheKVS.Get(key)
	if err != nil || data != nil {
		return
	}
	data, err = c.sourceKVS.Get(key)
	err = c.cacheKVS.Set(key, data)
	return
}

func (Cached) Set(key string, value []byte) error {
	panic("implement me")
}

func NewCached(source KVS, cache KVS) KVS {
	return &Cached{
		cache,
		source,
	}
}
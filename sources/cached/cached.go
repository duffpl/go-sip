package cached

import (
	"crypto"
	"fmt"
	"github.com/duffpl/go-sip/sources"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
)

type cachedDataSource struct {
	originDataSource sources.DataSource
	cacheDir         string
}

func (c *cachedDataSource) GetData(key string) ([]byte, error) {
	data, err := c.readDataFromFile(key)
	if err != nil {
		return nil, errors.Wrap(err, "get data from cached file")
	}
	if data != nil {
		return data, nil
	}
	data, err = c.originDataSource.GetData(key)
	if err != nil {
		return nil, errors.Wrap(err, "get data from origin source")
	}
	err = c.writeDataToFile(key, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *cachedDataSource) GetResourceId(key string) string {
	return "cached:" + c.originDataSource.GetResourceId(key)
}

func (c *cachedDataSource) writeDataToFile(key string, data []byte) error {
	cacheFilename, err := c.getCacheFilename(key)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(cacheFilename, data, 0600)
}

func (c *cachedDataSource) readDataFromFile(key string) (output []byte, err error) {
	cacheFilename, err := c.getCacheFilename(key)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(cacheFilename); os.IsNotExist(err) {
		return nil, nil
	}
	fh, err := os.Open(cacheFilename)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("cannot open cache file '%s'", cacheFilename))
	}
	defer func() {
		err = fh.Close()
		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("unable to close cache file '%s'", cacheFilename))
		}
	}()
	output, err = ioutil.ReadAll(fh)
	return
}

func (c *cachedDataSource) getCacheFilename(key string) (string, error) {
	cacheId, err := getCacheId(key)
	if err != nil {
		return "", errors.Wrap(err, "get cache filename")
	}
	return c.cacheDir + "/" + cacheId, nil
}

func NewCachedDataSource(cacheDir string, originSource sources.DataSource) sources.DataSource {
	return &cachedDataSource{
		cacheDir:         cacheDir,
		originDataSource: originSource,
	}
}

func calcMD5(input string) (checksum string, err error) {
	hasher := crypto.MD5.New()
	if _, err = hasher.Write([]byte(input)); err != nil {
		err = errors.Wrap(err, "md5 checksum")
	}
	checksum = fmt.Sprintf("%x", hasher.Sum(nil))
	return
}

func getCacheId(input string) (string, error) {
	return calcMD5(input)
}

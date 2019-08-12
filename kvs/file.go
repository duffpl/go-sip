package kvs

import (
	"os"
	"io/ioutil"
	"fmt"
	"crypto"
	"github.com/pkg/errors"
)

type KVS interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
}

func NewFileKVS(dir string) KVS {
	return &fileKVS{
		dir: dir,
	}
}

type fileKVS struct {
	dir string
}

func (kvs fileKVS) Get(key string) ([]byte, error) {
	keyFile := kvs.getFileName(key)
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, nil
	}
	fh, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	output, err := ioutil.ReadAll(fh)
	fh.Close()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (kvs fileKVS) Set(key string, value []byte) error {
	keyFile := kvs.getFileName(key)
	return ioutil.WriteFile(keyFile, value, 0644)
}

func (kvs fileKVS) getFileName(key string) string {
	hashedKey, _ := calcMD5(key)
	cacheFilename := kvs.dir + "/" + hashedKey
	return cacheFilename
}

func calcMD5(input string) (checksum string, err error) {
	hasher := crypto.MD5.New()
	if _, err = hasher.Write([]byte(input)); err != nil {
		err = errors.Wrap(err, "md5 checksum")
	}
	checksum = fmt.Sprintf("%x", hasher.Sum(nil))
	return
}

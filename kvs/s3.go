package kvs

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
)

type S3 struct {
	client *s3.S3
	bucket string
}

func (s S3) Get(key string) (data []byte, err error) {
	s3Response, err := s.client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return
	}
	data, err = ioutil.ReadAll(s3Response.Body)
	return
}

func (s S3) Set(key string, value []byte) error {
	panic("implement me")
}

func NewS3(client *s3.S3, bucket string) KVS {
	return &S3{
		client: client,
		bucket: bucket,
	}
}

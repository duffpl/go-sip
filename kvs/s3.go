package kvs

import (
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"os"
	"io/ioutil"
)

type S3 struct {
	client *s3.S3
}

func (s S3) Get(key string) (data []byte, err error) {
	s3Response, err := s.client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(os.Getenv("AWS_BUCKET")),
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

func NewS3(client *s3.S3) KVS {
	return &S3{
		client: client,
	}
}

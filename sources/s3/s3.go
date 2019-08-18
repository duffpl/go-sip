package s3

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/duffpl/go-sip/sources"
	"github.com/pkg/errors"
	"io/ioutil"
)

type s3SourceConfig struct {
	Bucket string `json:"bucket"`
}

type s3Source struct {
	bucket string
	client s3iface.S3API
}

func (source *s3Source) GetResourceId(key string) string {
	return "s3:" + source.bucket + "/" + key
}

func (source *s3Source) GetData(key string) (outputBytes []byte, err error) {
	output, err := source.client.GetObject(&s3.GetObjectInput{
		Bucket: &source.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("fetch data from s3. bucket: '%s', key: '%s'", source.bucket, key))
	}
	return ioutil.ReadAll(output.Body)
}

var awsSession *session.Session

func getS3Session(config s3SourceConfig) (*session.Session, error) {
	if awsSession != nil {
		return awsSession, nil
	}
	awsSession, err := session.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "get s3 session")
	}
	return awsSession, err
}

func init() {
	sources.RegisterDataSourceFactory("s3", func(jsonData []byte) (source sources.DataSource, err error) {
		var config s3SourceConfig
		err = json.Unmarshal(jsonData, &config)
		if err != nil {
			return nil, errors.Wrap(err, "s3 source factory")
		}
		awsSession, err := getS3Session(config)
		if err != nil {
			return nil, errors.Wrap(err, "s3 source factory")
		}
		s3Client := s3.New(awsSession)
		return &s3Source{
			bucket: config.Bucket,
			client: s3Client,
		}, nil
	})
}

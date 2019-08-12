package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/duffpl/go-sip/kvs"
	"github.com/h2non/bimg"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
)
const cacheDirFlagName = "cachedir"
func getCacheDir(c *cli.Context, cacheDirName string) (dir string, err error) {
	err = func() error {
		cacheRoot := c.String(cacheDirFlagName)
		dir = cacheRoot + "/" + cacheDirName
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		err = errors.Wrap(err, "cachedir")
	}
	return
}

type ByteKVS interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
}

type S3Source struct {
	client *s3.S3
	cache  ByteKVS
}

func (s *S3Source) fetchKey(key string) (data []byte, cacheHit bool, err error) {
	data, err = s.cache.Get(key)
	if err != nil {
		return
	}
	if data != nil {
		cacheHit = true
		return
	}
	s3Response, err := s.client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(os.Getenv("AWS_BUCKET")),
		Key:    aws.String(key),
	})
	if err != nil {
		return
	}
	data, err = ioutil.ReadAll(s3Response.Body)
	if err != nil {
		return
	}
	err = s.cache.Set(key, data)
	return

}

func main() {
	app := cli.NewApp()
	err := godotenv.Load()

	if err != nil {
		panic(err)
	}
	app.Version = "0.0.3";
	app.Commands = []cli.Command{
		{
			Name: "serve",
			Action: func(c *cli.Context) error {

				sigFile, err := os.Open("sig.key")
				if err != nil {
					return cli.NewExitError(errors.Wrap(err, "cannot open sig file"), 1)
				}
				sigKey, err := ioutil.ReadAll(sigFile)
				if err != nil {
					return cli.NewExitError(errors.Wrap(err, "cannot read sig key from file"), 1)
				}
				s3Client := s3.New(session.Must(session.NewSession()))
				processedCacheDir, err := getCacheDir(c,"processed-images")
				if err != nil {
					panic(err)
				}
				s3CacheDir, err := getCacheDir(c, "source-images")
				if err != nil {
					panic(err)
				}
				s3Cache := kvs.NewFileKVS(s3CacheDir)
				processedCache := kvs.NewFileKVS(processedCacheDir)
				s3KVS := kvs.NewS3(s3Client)
				cachedS3KVS := kvs.NewCached(s3KVS, s3Cache)
				http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
					err, code := func() (err error, status int) {
						if !verifySignature(request, sigKey) {
							return errors.New("invalid signature"), http.StatusForbidden
						}
						s3Key := request.URL.Path[1:]
						iW, iH, err := getImageSizeParamsFromRequest(request)
						if err != nil {
							return errors.Wrap(err, "invalid image params"), http.StatusPreconditionFailed
						}
						cX, cY, cW, cH, cropErr := getCropParamsFromRequest(request)
						var resizedKey string
						if cropErr == nil {
							resizedKey = fmt.Sprintf("%s-%d-%d-%d-%d-%d-%d", s3Key, iW, iH, cX, cY, cW, cH)
						} else {
							resizedKey = fmt.Sprintf("%s-%d-%d", s3Key, iW, iH)
						}
						data, err := processedCache.Get(resizedKey)
						if err != nil {
							return err, 500
						}
						if data != nil {
							writeImage(writer, data)
							return nil, 200
						}
						imageData, err := cachedS3KVS.Get(s3Key)
						if err != nil {
							return err, 500
						}
						img := bimg.NewImage(imageData)
						if cropErr == nil {
							extractedImg, err := img.Extract(cY, cX, cW, cH)
							if err != nil {
								return errors.Wrap(err, "cant extract"), 500
							}
							img = bimg.NewImage(extractedImg)
						}
						imageData, err = img.Process(bimg.Options{
							Type:    bimg.JPEG,
							Quality: 60,
							Width:   iW,
							Height:  iH,
							Enlarge: false,
						})
						if err != nil {
							return errors.Wrap(err, "cannot process image"), 500
						}
						writeImage(writer, imageData)
						return processedCache.Set(resizedKey, imageData), 500
					}()
					if err != nil {
						http.Error(writer, err.Error(), code)
					}
				})
				port := c.String("port")
				e := http.ListenAndServe(":"+port, nil)
				if e != nil {
					panic(e)
				}
				return nil
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "port",
					Value: "2222",
				},
				cli.StringFlag{
					Name:  cacheDirFlagName,
					Value: "/tmp/sip-cache",
				},

			},
		},
	}
	app.Run(os.Args)

}
func writeImage(writer http.ResponseWriter, imageData []byte) error {
	writer.Header()["Content-Length"] = []string{strconv.Itoa(len(imageData))}
	writer.Header().Add("Cache-Control", "max-age=31536000, public")
	writer.Header().Add("Content-Type", "image/jpeg")
	_, err := writer.Write(imageData)
	return err
}

func calcMD5(input string) (checksum string, err error) {
	hasher := crypto.MD5.New()
	if _, err = hasher.Write([]byte(input)); err != nil {
		err = errors.Wrap(err, "md5 checksum")
	}
	checksum = fmt.Sprintf("%x", hasher.Sum(nil))
	return
}

type ImageOperation func(image *bimg.Image) (*bimg.Image, error)

//func GetOperationsFromRequest(r *http.Request) []ImageOperation {
//	q := r.URL.Query()
//}

func NewCropOperation(cX, cY, cW, cH int) ImageOperation {
	return func(image *bimg.Image) (*bimg.Image, error) {
		_, err := image.Extract(cY, cX, cW, cH)
		if err != nil {
			return nil, errors.Wrap(err, "crop op")
		}
		return image, nil
	}
}

func NewResizeOperation(iW, iH int) ImageOperation {
	return func(image *bimg.Image) (*bimg.Image, error) {
		_, err := image.Resize(iW, iH)
		if err != nil {
			return nil, errors.Wrap(err, "resize op")
		}
		return image, nil
	}
}

func getImageSizeParamsFromRequest(r *http.Request) (w int, h int, err error) {
	q := r.URL.Query()
	w, err = getIntParam(q, "w", 0)
	h, err = getIntParam(q, "h", 0)
	return
}
func getIntParam(q url.Values, paramName string, defaultValue int) (result int, err error) {
	var cr int
	result = defaultValue
	param := q.Get(paramName)
	if param != "" {
		cr, err = strconv.Atoi(param)
		result = cr
	}
	return
}

func getCropParamsFromRequest(r *http.Request) (cx int, cy int, cw int, ch int, err error) {
	queryParams := r.URL.Query()
	cx, err = strconv.Atoi(queryParams.Get("cx"))
	cy, err = strconv.Atoi(queryParams.Get("cy"))
	ch, err = strconv.Atoi(queryParams.Get("ch"))
	cw, err = strconv.Atoi(queryParams.Get("cw"))
	return
}

func verifySignature(r *http.Request, sigKey []byte) bool {
	return true
	query := r.URL.Query()
	msg := struct {
		Path       string `json:"path"`
		Width      string `json:"w,omitempty"`
		Height     string `json:"h,omitempty"`
		CropX      string `json:"cx,omitempty"`
		CropY      string `json:"cy,omitempty"`
		CropWidth  string `json:"cw,omitempty"`
		CropHeight string `json:"ch,omitempty"`
	}{
		r.URL.Path,
		query.Get("w"),
		query.Get("h"),
		query.Get("cx"),
		query.Get("cy"),
		query.Get("cw"),
		query.Get("ch"),
	}
	shaMac := hmac.New(sha256.New, sigKey)
	msgJson, _ := json.Marshal(msg)
	shaMac.Write(msgJson)
	fmt.Println(string(msgJson))
	resultSig := fmt.Sprintf("%x", shaMac.Sum(nil))
	return resultSig == r.URL.Query().Get("sig")
}

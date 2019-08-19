package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/duffpl/go-sip/kvs"
	"github.com/duffpl/go-sip/matcher"
	"github.com/duffpl/go-sip/sources"
	"github.com/duffpl/go-sip/sources/cached"
	_ "github.com/duffpl/go-sip/sources/s3"
	"github.com/h2non/bimg"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
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

func GetMatchersFromConfig(configFilename string) (matchers []matcher.Matcher, err error) {
	data, _ := ioutil.ReadFile(configFilename)
	var matcherConfigs []matcher.MatcherConfig
	err = json.Unmarshal(data, &matcherConfigs)
	if err != nil {
		return nil, errors.Wrap(err, "matchers config loader")
	}
	for _, matcherConfig := range matcherConfigs {
		newMatcher, err := matcher.NewMatcher(matcherConfig)
		matchers = append(matchers, newMatcher)
		if err != nil {
			return nil, errors.Wrap(err, "creating matcher")
		}
	}
	return
}
func main() {

	app := cli.NewApp()
	err := godotenv.Load()

	if err != nil {
		panic(err)
	}
	app.Version = "0.0.3"
	app.Commands = []cli.Command{
		{
			Name: "serve",
			Action: func(c *cli.Context) error {
				cachedSources := make(map[sources.DataSource]sources.DataSource)
				cachedSourcesMapMutex := &sync.RWMutex{}
				sigFile, err := os.Open("sig.key")
				if err != nil {
					return cli.NewExitError(errors.Wrap(err, "cannot open sig file"), 1)
				}
				sigKey, err := ioutil.ReadAll(sigFile)
				if err != nil {
					return cli.NewExitError(errors.Wrap(err, "cannot read sig key from file"), 1)
				}
				processedCacheDir, err := getCacheDir(c, "processed-images")
				if err != nil {
					panic(err)
				}
				sourceCacheDir, err := getCacheDir(c, "source-images")
				if err != nil {
					panic(err)
				}
				matchers, err := GetMatchersFromConfig("sources.json")
				processedCache := kvs.NewFileKVS(processedCacheDir)
				http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
					err, code := func() (err error, status int) {
						var sourceMatcher matcher.Matcher
						for _, currentMatcher := range matchers {
							if currentMatcher.HasMatched(request) {
								sourceMatcher = currentMatcher
								break
							}
						}
						if sourceMatcher == nil {
							return errors.New("No source matched for current request"), http.StatusBadRequest
						}
						rewrittenPath, err := sourceMatcher.RewritePath(request)
						if err != nil {
							return errors.Wrap(err, "path rewrite"), http.StatusBadRequest
						}
						if !verifySignature(request, sigKey) {
							return errors.New("invalid signature"), http.StatusForbidden
						}
						iW, iH, err := getImageSizeParamsFromRequest(request)
						if err != nil {
							return errors.Wrap(err, "invalid image params"), http.StatusPreconditionFailed
						}
						cX, cY, cW, cH, cropErr := getCropParamsFromRequest(request)
						var resizedKey string
						dataSource := sourceMatcher.GetSource()
						cachedSourcesMapMutex.RLock()
						if cachedDataSource, found := cachedSources[dataSource]; !found {
							cachedSourcesMapMutex.RUnlock()
							cachedDataSource = cached.NewCachedDataSource(sourceCacheDir, dataSource)
							cachedSourcesMapMutex.Lock()
							cachedSources[dataSource] = cachedDataSource
							cachedSourcesMapMutex.Unlock()
							dataSource = cachedDataSource
						} else {
							dataSource = cachedDataSource
						}
						sourceItemKey := dataSource.GetResourceId(rewrittenPath)
						if cropErr == nil {
							resizedKey = fmt.Sprintf("%s-%d-%d-%d-%d-%d-%d", sourceItemKey, iW, iH, cX, cY, cW, cH)
						} else {
							resizedKey = fmt.Sprintf("%s-%d-%d", sourceItemKey, iW, iH)
						}
						data, err := processedCache.Get(resizedKey)
						if err != nil {
							return err, 500
						}
						if data != nil {
							writeImage(writer, data)
							return nil, 200
						}
						sourceData, err := dataSource.GetData(rewrittenPath)
						if err != nil {
							return errors.Wrap(err, "fetch data from source cache"), http.StatusBadRequest
						}
						img := bimg.NewImage(sourceData)
						if cropErr == nil {
							extractedImg, err := img.Extract(cY, cX, cW, cH)
							if err != nil {
								return errors.Wrap(err, "cant extract"), 500
							}
							img = bimg.NewImage(extractedImg)
						}
						imageData, err := img.Process(bimg.Options{
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
				fmt.Printf("Image server will listen on port '%s'", port)
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
					Value: "/tmp/sip-cache-v2",
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

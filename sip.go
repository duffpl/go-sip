package main

import (
	"bytes"
	"github.com/anthonynsimon/bild/transform"
	"github.com/chai2010/webp"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"io"
	"log"
	"math"
	_ "net/http/pprof"
	"regexp"
	"strings"
)
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/duffpl/go-sip/kvs"
	"github.com/duffpl/go-sip/matcher"
	"github.com/duffpl/go-sip/sources"
	"github.com/duffpl/go-sip/sources/cached"
	_ "github.com/duffpl/go-sip/sources/s3"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

const cacheDirFlagName = "cachedir"
const disableVipsCacheFlagName = "disableVipsCache"
const enableSignedRequestsFlagName = "enableSignedRequests"
const defaultImageQualityFlagName = "defaultImageQuality"

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
	app.Version = "0.0.7"
	app.Commands = []cli.Command{
		{
			Name: "serve",
			Action: func(c *cli.Context) error {
				cachedSources := make(map[sources.DataSource]sources.DataSource)
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
				signedRequestsEnabled := c.Bool(enableSignedRequestsFlagName)
				defaultImageQuality := c.Int(defaultImageQualityFlagName)
				matchers, err := GetMatchersFromConfig("sources.json")
				processedCache := kvs.NewFileKVS(processedCacheDir)
				requestNumber := 0
				//processMutex := sync.Mutex{}
				for _, requestMatcher := range matchers {
					matcherSource := requestMatcher.GetSource()
					cachedSources[matcherSource] = cached.NewCachedDataSource(sourceCacheDir, requestMatcher.GetSource())
				}
				http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
					err, code := func() (err error, status int) {
						var cacheKeyTokens []interface{}
						requestHasBeenCanceled := false
						go func() {
							select {
							case <-request.Context().Done():
								requestHasBeenCanceled = true
								fmt.Println("[BYE]")
								return
							}
						}()
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
						dataSource := cachedSources[sourceMatcher.GetSource()]
						rewrittenPath, err := sourceMatcher.RewritePath(request)
						if err != nil {
							return errors.Wrap(err, "path rewrite"), http.StatusBadRequest
						}
						if signedRequestsEnabled && !verifySignature(request, sigKey) {
							return errors.New("invalid signature"), http.StatusForbidden
						}
						iW, iH, err := getImageSizeParamsFromRequest(request)
						if err != nil {
							return errors.Wrap(err, "invalid image params"), http.StatusPreconditionFailed
						}
						cacheKeyTokens = append(cacheKeyTokens, iW, iH)
						cX, cY, cW, cH, cropErr := getCropParamsFromRequest(request)
						sourceItemKey := dataSource.GetResourceId(rewrittenPath)
						cacheKeyTokens = append(cacheKeyTokens, sourceItemKey)
						if cropErr == nil {
							cacheKeyTokens = append(cacheKeyTokens, cX, cY, cW, cH)
						}
						imageQuality, _ := strconv.Atoi(request.URL.Query().Get("q"))
						if imageQuality == 0 {
							imageQuality = defaultImageQuality
						}
						cacheKeyTokens = append(cacheKeyTokens, imageQuality)
						if requestHasBeenCanceled {
							return nil, 200
						}
						pLeft, pRight, pTop, pBottom := getPaddingParamsFromRequest(request)
						cacheKeyTokens = append(cacheKeyTokens, pLeft, pRight, pTop, pBottom)
						var webPAccepted bool
						if isWebPAccepted(request) {
							webPAccepted = true
							fmt.Println("webp!")
							cacheKeyTokens = append(cacheKeyTokens, "webp")
						} else {
							webPAccepted = false
							cacheKeyTokens = append(cacheKeyTokens, "jpeg")
						}
						filter := getResampleFilter(request)
						cacheKeyTokens = append(cacheKeyTokens, filter)
						resizedKey := joinItems(cacheKeyTokens)
						data, err := processedCache.Get(resizedKey)
						if err != nil {
							return err, 500
						}
						if data != nil {
							if webPAccepted {
								_ = writeWebP(writer, data)
							} else {
								_ = writeJpeg(writer, data)
							}
							return nil, 200
						}
						if requestHasBeenCanceled {
							return nil, 200
						}
						sourceData, err := dataSource.GetData(rewrittenPath)
						if err != nil {
							return errors.Wrap(err, "fetch data from source cache"), http.StatusBadRequest
						}
						if requestHasBeenCanceled {
							return nil, 200
						}
						img, _, err := image.Decode(bytes.NewReader(sourceData))
						if !allZeroes(pTop, pBottom, pLeft, pRight) {
							img = getPaddedImage(img, pLeft, pRight, pTop, pBottom)
						}
						if err != nil {
							return err, 500
						}
						if cropErr == nil && noZeroes(cW, cH) {
							img = transform.Crop(img, image.Rect(cX, cY, cX+cW, cY+cH))
						}
						if requestHasBeenCanceled {
							return nil, 200
						}
						imageBounds := img.Bounds()
						imageRatio := float64(imageBounds.Dx()) / float64(imageBounds.Dy())
						if iW == 0 {
							iW = int(math.Floor(float64(iH) * imageRatio))
						}
						if iH == 0 {
							iH = int(math.Floor(float64(iW) / imageRatio))
						}
						if noZeroes(iW, iH) && iW < imageBounds.Dx() && iH < imageBounds.Dy() {
							img = transform.Resize(img, iW, iH, filter)
						}
						if requestHasBeenCanceled {
							return nil, 200
						}
						var imageOutput bytes.Buffer
						if webPAccepted {
							err = encodeWebP(&imageOutput, img, imageQuality)
						} else {
							err = encodeJpeg(&imageOutput, img, imageQuality)
						}
						if err != nil {
							return err, 500
						}
						outputBytes := imageOutput.Bytes()
						if webPAccepted {
							_ = writeWebP(writer, outputBytes)
						} else {
							_ = writeJpeg(writer, outputBytes)
						}
						requestNumber += 1
						fmt.Printf("finished request #%d\n", requestNumber)
						if request.URL.Query().Get("temporary") == "1" {
							return nil, 200
						}
						err = processedCache.Set(resizedKey, outputBytes)
						return
					}()
					if err != nil {
						http.Error(writer, err.Error(), code)
					}
				})
				port := c.String("port")
				fmt.Printf("Image server will listen on port '%s'", port)
				go func() {
					log.Println(http.ListenAndServe(":6060", nil))
				}()
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
				cli.BoolFlag{
					Name: disableVipsCacheFlagName,
				},
				cli.BoolFlag{
					Name: enableSignedRequestsFlagName,
				},
				cli.IntFlag{
					Name:  defaultImageQualityFlagName,
					Value: 85,
				},
			},
		},
	}
	_ = app.Run(os.Args)

}

func encodeJpeg(writer io.Writer, img image.Image, quality int) error {
	return jpeg.Encode(writer, img, &jpeg.Options{Quality: quality})
}

func encodeWebP(writer io.Writer, img image.Image, quality int) error {
	options := webp.Options{}
	if quality == 100 {
		options.Lossless = true
	} else {
		options.Quality = float32(quality)
	}
	return webp.Encode(writer, img, &options)
}

var webPRegexp = regexp.MustCompile("image/webp")

func isWebPAccepted(request *http.Request) bool {
	accept := request.Header.Get("accept")
	return webPRegexp.MatchString(accept)
}

func getPaddedImage(input image.Image, pL int, pR int, pT int, pB int) image.Image {
	w := input.Bounds().Dx()
	h := input.Bounds().Dy()
	targetRectangle := image.Rect(0, 0, w+pL+pR, h+pT+pB)
	white := color.RGBA{255, 255, 255, 255}
	resultImage := image.NewRGBA(targetRectangle)
	draw.Draw(resultImage, resultImage.Bounds(), &image.Uniform{white}, image.Point{}, draw.Src)
	draw.Draw(resultImage, image.Rect(pR, pT, pR+w, pT+h), input, image.Point{}, draw.Src)
	return resultImage
}

func joinItems(items []interface{}) string {
	var result []string
	for _, item := range items {
		result = append(result, fmt.Sprint(item))
	}
	return strings.Join(result, "-")
}

func noZeroes(values ...int) bool {
	for _, value := range values {
		if value == 0 {
			return false
		}
	}
	return true
}

func allZeroes(values ...int) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}

func writeJpeg(writer http.ResponseWriter, imageData []byte) error {
	return writeImage(writer, imageData, "image/jpeg")
}

func writeWebP(writer http.ResponseWriter, imageData []byte) error {
	return writeImage(writer, imageData, "image/webp")
}

func writeImage(writer http.ResponseWriter, imageData []byte, contentType string) error {
	header := writer.Header()
	header["Content-Length"] = []string{strconv.Itoa(len(imageData))}
	header.Add("Cache-Control", "max-age=31536000, public")
	header.Add("Content-Type", contentType)
	header.Add("Access-Control-Allow-Origin", "*")
	_, err := writer.Write(imageData)
	return err
}

//func calcMD5(input string) (checksum string, err error) {
//	hasher := crypto.MD5.New()
//	if _, err = hasher.Write([]byte(input)); err != nil {
//		err = errors.Wrap(err, "md5 checksum")
//	}
//	checksum = fmt.Sprintf("%x", hasher.Sum(nil))
//	return
//}

//func NewCropOperation(cX, cY, cW, cH int) ImageOperation {
//	return func(image *bimg.Image) (*bimg.Image, error) {
//		_, err := image.Extract(cY, cX, cW, cH)
//		if err != nil {
//			return nil, errors.Wrap(err, "crop op")
//		}
//		return image, nil
//	}
//}
//
//func NewResizeOperation(iW, iH int) ImageOperation {
//	return func(image *bimg.Image) (*bimg.Image, error) {
//		_, err := image.Resize(iW, iH)
//		if err != nil {
//			return nil, errors.Wrap(err, "resize op")
//		}
//		return image, nil
//	}
//}

func getResampleFilter(request *http.Request) transform.ResampleFilter {
	name := request.URL.Query().Get("t")
	switch name {
	case "lanczos":
		return transform.Lanczos
	case "linear":
		return transform.Linear
	case "box":
		return transform.Box
	case "gaussian":
		return transform.Gaussian
	default:
		return transform.Lanczos
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

func getPaddingParamsFromRequest(r *http.Request) (pRight int, pLeft int, pTop int, pBottom int) {
	queryParams := r.URL.Query()
	pRight, _ = strconv.Atoi(queryParams.Get("pr"))
	pLeft, _ = strconv.Atoi(queryParams.Get("pl"))
	pTop, _ = strconv.Atoi(queryParams.Get("pt"))
	pBottom, _ = strconv.Atoi(queryParams.Get("pb"))
	return
}

func verifySignature(r *http.Request, sigKey []byte) bool {
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
	resultSig := fmt.Sprintf("%x", shaMac.Sum(nil))
	return resultSig == r.URL.Query().Get("sig")
}

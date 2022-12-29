package infra

const (
	UserCollection = "user"
)

var (
	AccessKey string
	SecretKey string

	ApiAuth   bool
	InnerAuth map[string]string
	Secret    string

	SvrAK string
	SvrSK string

	SdAK string
	SdSK string
)

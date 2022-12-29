package infra

import (
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	MongoClient   *mongo.Client
	MongoDatabase string

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

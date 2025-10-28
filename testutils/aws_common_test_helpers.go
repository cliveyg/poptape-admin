package testutils

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

const DefaultAWSRegion = "us-east-1"

// GetAWSEndpointFromEnv returns the AWS endpoint URL read from the environment.
func GetAWSEndpointFromEnv() string {
	return os.Getenv("AWS_ENDPOINT_URL")
}

// GetAWSRegionFromEnv returns the AWS region read from the environment,
// falling back to DefaultAWSRegion when not set.
func GetAWSRegionFromEnv() string {
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r
	}
	return DefaultAWSRegion
}

// AWSResolverFromEnv returns an aws.EndpointResolverWithOptionsFunc that resolves
// to the AWS_ENDPOINT_URL (if set) using the region from env.
func AWSResolverFromEnv() aws.EndpointResolverWithOptionsFunc {
	endpoint := GetAWSEndpointFromEnv()
	region := GetAWSRegionFromEnv()
	return aws.EndpointResolverWithOptionsFunc(func(service, r string, options ...interface{}) (aws.Endpoint, error) {
		if endpoint != "" {
			return aws.Endpoint{
				URL:           endpoint,
				SigningRegion: region,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
}

// LoadDefaultAWSConfig loads an aws.Config suitable for tests. If AWS_ENDPOINT_URL
// is set the returned config will be wired to that endpoint (useful for LocalStack).
// Caller must pass a context.Context.
func LoadDefaultAWSConfig(ctx context.Context) (aws.Config, error) {
	region := GetAWSRegionFromEnv()
	endpoint := GetAWSEndpointFromEnv()
	if endpoint != "" {
		return config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithEndpointResolverWithOptions(AWSResolverFromEnv()),
		)
	}
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

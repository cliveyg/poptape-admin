package testutils

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestAWSConfig loads AWS config using env vars, with support for endpoint override (e.g. Localstack).
func TestAWSConfig(t *testing.T) aws.Config {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(os.Getenv("AWS_REGION")),
	}
	// Optionally support LOCALSTACK_ENDPOINT or AWS_ENDPOINT env var override
	if ep := os.Getenv("AWS_ENDPOINT"); ep != "" {
		opts = append(opts, config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: ep, SigningRegion: region}, nil
				},
			),
		))
	} else if ep := os.Getenv("LOCALSTACK_ENDPOINT"); ep != "" {
		opts = append(opts, config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: ep, SigningRegion: region}, nil
				},
			),
		))
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}
	return cfg
}

// TestAWSListS3Buckets is a simple AWS smoketest for S3 (works with Localstack).
func TestAWSListS3Buckets(t *testing.T, cfg aws.Config) []string {
	client := s3.NewFromConfig(cfg)
	resp, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("Failed to list S3 buckets: %v", err)
	}
	names := make([]string, 0, len(resp.Buckets))
	for _, b := range resp.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}
	return names
}

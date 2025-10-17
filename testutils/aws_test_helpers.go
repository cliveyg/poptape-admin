package testutils

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cliveyg/poptape-admin/app"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// GetAWSIAMClient returns a configured IAM client for LocalStack.
func GetAWSIAMClient(ctx context.Context) *iam.Client {
	awsEndpoint := os.Getenv("AWS_ENDPOINT_URL")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				if awsEndpoint != "" {
					return aws.Endpoint{
						URL:           awsEndpoint,
						SigningRegion: region,
					}, nil
				}
				return aws.Endpoint{}, &aws.EndpointNotFoundError{}
			}),
		),
	)
	if err != nil {
		log.Fatalf("unable to load SDK config for test: %v", err)
	}
	return iam.NewFromConfig(cfg)
}

// SeedIAMUsers creates a list of IAM users in LocalStack. Each user is created with the provided path.
// Returns a cleanup function to delete those users.
func SeedIAMUsers(ctx context.Context, client *iam.Client, usernames []string, path string) (cleanup func()) {
	for _, username := range usernames {
		_, err := client.CreateUser(ctx, &iam.CreateUserInput{
			UserName: aws.String(username),
			Path:     aws.String(path),
		})
		if err != nil {
			log.Fatalf("failed to create test IAM user %s: %v", username, err)
		}
	}

	// Cleanup function to remove seeded users
	return func() {
		for _, username := range usernames {
			_, err := client.DeleteUser(ctx, &iam.DeleteUserInput{
				UserName: aws.String(username),
			})
			if err != nil {
				log.Printf("failed to cleanup IAM user %s: %v", username, err)
			}
		}
	}
}

// ClearAllIAMUsers deletes all IAM users from LocalStack.
func ClearAllIAMUsers(ctx context.Context, client *iam.Client) {
	// List all users
	output, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		log.Fatalf("failed to list IAM users: %v", err)
	}
	for _, user := range output.Users {
		_, err := client.DeleteUser(ctx, &iam.DeleteUserInput{
			UserName: user.UserName,
		})
		if err != nil {
			log.Printf("failed to delete IAM user %s: %v", aws.ToString(user.UserName), err)
		}
	}
}

// WaitForLocalStackIAM polls IAM ListUsers until LocalStack IAM is responsive.
// Useful if your tests run immediately after container startup.
func WaitForLocalStackIAM(ctx context.Context, client *iam.Client, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := client.ListUsers(ctx, &iam.ListUsersInput{})
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

func SeedIAMUsersWithPaths(ctx context.Context, client *iam.Client, users map[string]string) (cleanup func()) {
	created := []string{}
	for username, path := range users {
		_, err := client.CreateUser(ctx, &iam.CreateUserInput{
			UserName: aws.String(username),
			Path:     aws.String(path),
		})
		if err != nil {
			log.Fatalf("failed to create test IAM user %s: %v", username, err)
		}
		created = append(created, username)
	}
	return func() {
		for _, username := range created {
			_, err := client.DeleteUser(ctx, &iam.DeleteUserInput{
				UserName: aws.String(username),
			})
			if err != nil {
				log.Printf("failed to cleanup IAM user %s: %v", username, err)
			}
		}
	}
}

// GetAllIAMUsers fetches all IAM users from LocalStack (for assertions/debug).
func GetAllIAMUsers(ctx context.Context, client *iam.Client) ([]types.User, error) {
	out, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	return out.Users, nil
}

// MockAWSAdminError is a test utility mock for AWSAdminInterface that always returns an error from ListAllUsers.
// All other interface methods are stubbed out with zero values.
type MockAWSAdminError struct{}

func (m *MockAWSAdminError) TestConnection(ctx context.Context) error {
	return nil
}

func (m *MockAWSAdminError) CreateUserWithAccessKey(ctx context.Context, userName string) (*iamtypes.AccessKey, error) {
	return nil, nil
}

func (m *MockAWSAdminError) DeleteUserCompletely(ctx context.Context, userName string) error {
	return nil
}

func (m *MockAWSAdminError) ListAllUsers(ctx context.Context) ([]iamtypes.User, error) {
	return nil, fmt.Errorf("mock AWS error")
}

func (m *MockAWSAdminError) CreateBucket(ctx context.Context, bucketName string) error {
	return nil
}

func (m *MockAWSAdminError) EmptyBucket(ctx context.Context, bucketName string) error {
	return nil
}

func (m *MockAWSAdminError) DeleteBucketCompletely(ctx context.Context, bucketName string) error {
	return nil
}

func (m *MockAWSAdminError) ListAllStandardBuckets(ctx context.Context) ([]s3types.Bucket, error) {
	return nil, nil
}

// MakeTestUser returns a valid test user with the "super" role.
func MakeTestUser() app.User {
	return app.User{
		AdminId:   uuid.New(),
		Username:  "testsuper",
		Password:  []byte("password"),
		LastLogin: time.Now(),
		Active:    true,
		Validated: true,
		Roles:     []app.Role{{Name: "super"}},
		Created:   time.Now(),
		Updated:   time.Now(),
		Deleted:   gorm.DeletedAt{},
	}
}

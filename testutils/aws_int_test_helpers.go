package testutils

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/cliveyg/poptape-admin/app"
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Integration helpers keep concrete SDK signatures so existing integration tests do not need changes.

// GetAWSIAMClient returns a configured IAM client for LocalStack or real AWS depending on env.
func GetAWSIAMClient(ctx context.Context) *iam.Client {
	cfg, err := LoadDefaultAWSConfig(ctx)
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

// SeedIAMUsersWithPaths seeds users with specific paths and returns cleanup func.
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
func GetAllIAMUsers(ctx context.Context, client *iam.Client) ([]iamtypes.User, error) {
	out, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	return out.Users, nil
}

// GetAWSS3Client returns a configured S3 client for LocalStack (concrete *s3.Client).
func GetAWSS3Client(ctx context.Context) *s3.Client {
	cfg, err := LoadDefaultAWSConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config for test: %v", err)
	}
	return s3.NewFromConfig(cfg)
}

// CreateS3Bucket creates a bucket by name (ignores errors if already exists).
func CreateS3Bucket(ctx context.Context, s3Client *s3.Client, name string) error {
	_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &name,
	})
	return err
}

// DeleteS3Bucket deletes a bucket by name (ignores errors if not exists).
func DeleteS3Bucket(ctx context.Context, s3Client *s3.Client, name string) error {
	_, err := s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &name,
	})
	return err
}

// ClearAllS3Buckets deletes all buckets (use with caution in test environment).
func ClearAllS3Buckets(ctx context.Context, s3Client *s3.Client) error {
	out, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return err
	}
	for _, b := range out.Buckets {
		if b.Name != nil {
			_ = DeleteS3Bucket(ctx, s3Client, *b.Name)
		}
	}
	return nil
}

// SeedS3Buckets creates all given buckets and returns a cleanup func.
func SeedS3Buckets(ctx context.Context, s3Client *s3.Client, bucketNames []string) func() {
	for _, name := range bucketNames {
		_ = CreateS3Bucket(ctx, s3Client, name)
	}
	return func() {
		for _, name := range bucketNames {
			_ = DeleteS3Bucket(ctx, s3Client, name)
		}
	}
}

// MockAWSAdminError is a test utility mock for AWSAdminInterface that always returns an error from ListAllUsers.
// Kept for compatibility with existing integration tests that use it.
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
	return nil, fmt.Errorf("mock AWS ListAllUsers error")
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
	return nil, fmt.Errorf("mock AWS ListAllStandardBuckets error")
}

// Compile-time interface check (keeps integration tests that depend on this type compiling).
var _ awsutil.AWSAdminInterface = (*MockAWSAdminError)(nil)

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

// NewTestAppWithMockAWS returns a shallow-copied App with AWS replaced by MockAWSAdminError.
func NewTestAppWithMockAWS(TestApp *app.App) *app.App {
	return &app.App{
		Router:        gin.New(),
		DB:            TestApp.DB,
		Log:           TestApp.Log,
		Mongo:         TestApp.Mongo,
		AWS:           &MockAWSAdminError{},
		CommandRunner: TestApp.CommandRunner,
	}
}

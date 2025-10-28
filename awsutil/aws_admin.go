package awsutil

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/rs/zerolog"
)

type AWSAdmin struct {
	IAM IAMAPI
	S3  S3API
	Log *zerolog.Logger
}

// AWSAdminInterface describes the operations exposed by AWSAdmin.
type AWSAdminInterface interface {
	TestConnection(ctx context.Context) error
	CreateUserWithAccessKey(ctx context.Context, userName string) (*iamtypes.AccessKey, error)
	DeleteUserCompletely(ctx context.Context, userName string) error
	ListAllUsers(ctx context.Context) ([]iamtypes.User, error)
	CreateBucket(ctx context.Context, bucketName string) error
	EmptyBucket(ctx context.Context, bucketName string) error
	DeleteBucketCompletely(ctx context.Context, bucketName string) error
	ListAllStandardBuckets(ctx context.Context) ([]s3types.Bucket, error)
}

// NewAWSAdmin constructs concrete SDK clients and assigns them to the interface fields.
func NewAWSAdmin(ctx context.Context, logger *zerolog.Logger) (*AWSAdmin, error) {
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	var cfg aws.Config
	var err error

	if endpoint != "" {
		logger.Debug().Msgf("Using LocalStack AWS endpoint: %s", endpoint)
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithEndpointResolverWithOptions(LocalStackResolver{Endpoint: endpoint}),
		)
	} else {
		logger.Debug().Msg("Using default AWS endpoints")
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		logger.Error().Err(err).Msg("AWS config error")
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	iamClient := iam.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	return &AWSAdmin{
		IAM: iamClient,
		S3:  s3Client,
		Log: logger,
	}, nil
}

// LocalStackResolver provides a custom endpoint for the AWS SDK.
type LocalStackResolver struct {
	Endpoint string
}

func (r LocalStackResolver) ResolveEndpoint(service, region string, options ...interface{}) (aws.Endpoint, error) {
	_ = options
	if r.Endpoint != "" {
		return aws.Endpoint{
			URL:               r.Endpoint,
			SigningRegion:     region,
			HostnameImmutable: true,
		}, nil
	}
	return aws.Endpoint{}, &aws.EndpointNotFoundError{}
}

// TestConnection does small IAM + S3 checks; uses marker/next-marker pagination to avoid IsTruncated pointer issues.
func (aw *AWSAdmin) TestConnection(ctx context.Context) error {
	if aw.IAM == nil || aw.S3 == nil {
		return fmt.Errorf("AWSAdmin not properly initialised")
	}

	// collect users using marker field only (works regardless of SDK bool pointer shape)
	var collectedUsers []iamtypes.User
	marker := ""
	for {
		req := &iam.ListUsersInput{}
		if marker != "" {
			req.Marker = aws.String(marker)
		}
		out, err := aw.IAM.ListUsers(ctx, req)
		if err != nil {
			aw.Log.Error().Err(err).Msg("IAM connection test failed")
			return fmt.Errorf("IAM connection test failed: %w", err)
		}
		collectedUsers = append(collectedUsers, out.Users...)
		// Continue if Marker is present (some SDKs set Marker for next page)
		if out.Marker != nil && *out.Marker != "" {
			marker = *out.Marker
			continue
		}
		break
	}

	// Test S3: List buckets
	bucks, err := aw.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		aw.Log.Error().Err(err).Msg("S3 connection test failed")
		return fmt.Errorf("S3 connection test failed: %w", err)
	}

	if os.Getenv("ENVIRONMENT") == "DEV" {
		for _, user := range collectedUsers {
			uname := ""
			arn := ""
			if user.UserName != nil {
				uname = *user.UserName
			}
			if user.Arn != nil {
				arn = *user.Arn
			}
			aw.Log.Debug().Msgf("Username [%s], ARN [%s] Created [%s]", uname, arn, user.CreateDate)
		}
		for _, b := range bucks.Buckets {
			bname := ""
			if b.Name != nil {
				bname = *b.Name
			}
			arn := fmt.Sprintf("arn:aws:s3:::%s", bname)
			aw.Log.Debug().Msgf("Bucket name [%s], ARN [%s] Created [%s]", bname, arn, b.CreationDate)
		}
	}

	return nil
}

// CreateUserWithAccessKey creates an IAM user and an access key for them.
func (aw *AWSAdmin) CreateUserWithAccessKey(ctx context.Context, userName string) (*iamtypes.AccessKey, error) {
	aw.Log.Info().Str("user", userName).Msg("Creating IAM user")
	_, err := aw.IAM.CreateUser(ctx, &iam.CreateUserInput{UserName: &userName})
	if err != nil {
		aw.Log.Error().Err(err).Str("user", userName).Msg("Failed to create user")
		return nil, err
	}
	aw.Log.Info().Str("user", userName).Msg("Creating access key")
	keyOut, err := aw.IAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &userName})
	if err != nil {
		aw.Log.Error().Err(err).Str("user", userName).Msg("Failed to create access key")
		return nil, err
	}
	return keyOut.AccessKey, nil
}

// DeleteUserCompletely removes associated IAM resources then deletes the user.
func (aw *AWSAdmin) DeleteUserCompletely(ctx context.Context, userName string) error {
	aw.Log.Info().Str("user", userName).Msg("Deleting IAM user and all attached resources")

	keys, _ := aw.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName})
	for _, ak := range keys.AccessKeyMetadata {
		_, err := aw.IAM.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: &userName, AccessKeyId: ak.AccessKeyId})
		if err != nil {
			if ak.AccessKeyId != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("accessKeyId", *ak.AccessKeyId).Msg("Failed to delete access key")
			} else {
				aw.Log.Error().Err(err).Str("user", userName).Msg("Failed to delete access key")
			}
		}
	}

	pols, _ := aw.IAM.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &userName})
	for _, pol := range pols.PolicyNames {
		_, err := aw.IAM.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: &pol})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("policy", pol).Msg("Failed to delete inline policy")
		}
	}

	mpols, _ := aw.IAM.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &userName})
	for _, mp := range mpols.AttachedPolicies {
		if mp.PolicyArn != nil {
			_, err := aw.IAM.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: &userName, PolicyArn: mp.PolicyArn})
			if err != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("policyArn", *mp.PolicyArn).Msg("Failed to detach managed policy")
			}
		}
	}

	grps, _ := aw.IAM.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &userName})
	for _, grp := range grps.Groups {
		if grp.GroupName != nil {
			_, err := aw.IAM.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: &userName, GroupName: grp.GroupName})
			if err != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("group", *grp.GroupName).Msg("Failed to remove user from group")
			}
		}
	}

	_, _ = aw.IAM.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: &userName})

	certs, _ := aw.IAM.ListSigningCertificates(ctx, &iam.ListSigningCertificatesInput{UserName: &userName})
	for _, cert := range certs.Certificates {
		if cert.CertificateId != nil {
			_, err := aw.IAM.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: &userName, CertificateId: cert.CertificateId})
			if err != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("certID", *cert.CertificateId).Msg("Failed to delete signing certificate")
			}
		}
	}

	mfas, _ := aw.IAM.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &userName})
	for _, mfa := range mfas.MFADevices {
		if mfa.SerialNumber != nil {
			_, _ = aw.IAM.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: &userName, SerialNumber: mfa.SerialNumber})
			_, _ = aw.IAM.DeleteVirtualMFADevice(ctx, &iam.DeleteVirtualMFADeviceInput{SerialNumber: mfa.SerialNumber})
		}
	}

	sshkeys, _ := aw.IAM.ListSSHPublicKeys(ctx, &iam.ListSSHPublicKeysInput{UserName: &userName})
	for _, key := range sshkeys.SSHPublicKeys {
		if key.SSHPublicKeyId != nil {
			_, err := aw.IAM.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: &userName, SSHPublicKeyId: key.SSHPublicKeyId})
			if err != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("sshKeyId", *key.SSHPublicKeyId).Msg("Failed to delete SSH public key")
			}
		}
	}

	sscs, _ := aw.IAM.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: &userName})
	for _, cred := range sscs.ServiceSpecificCredentials {
		if cred.ServiceSpecificCredentialId != nil {
			_, err := aw.IAM.DeleteServiceSpecificCredential(ctx, &iam.DeleteServiceSpecificCredentialInput{UserName: &userName, ServiceSpecificCredentialId: cred.ServiceSpecificCredentialId})
			if err != nil {
				aw.Log.Error().Err(err).Str("user", userName).Str("serviceCredId", *cred.ServiceSpecificCredentialId).Msg("Failed to delete service-specific credential")
			}
		}
	}

	_, err := aw.IAM.DeleteUser(ctx, &iam.DeleteUserInput{UserName: &userName})
	if err != nil {
		aw.Log.Error().Err(err).Str("user", userName).Msg("Failed to delete IAM user")
		return err
	}
	aw.Log.Info().Str("user", userName).Msg("Deleted IAM user successfully")
	return nil
}

// ListAllUsers paginates using Marker (works with concrete SDKs and fakes).
func (aw *AWSAdmin) ListAllUsers(ctx context.Context) ([]iamtypes.User, error) {
	var users []iamtypes.User
	marker := ""
	for {
		req := &iam.ListUsersInput{}
		if marker != "" {
			req.Marker = aws.String(marker)
		}
		out, err := aw.IAM.ListUsers(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}
		users = append(users, out.Users...)
		if out.Marker != nil && *out.Marker != "" {
			marker = *out.Marker
			continue
		}
		break
	}
	return users, nil
}

// CreateBucket uses the S3API CreateBucket call.
func (aw *AWSAdmin) CreateBucket(ctx context.Context, bucketName string) error {
	aw.Log.Info().Str("bucket", bucketName).Msg("Creating S3 bucket")
	_, err := aw.S3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucketName})
	return err
}

// EmptyBucket removes all object versions and delete markers using ListObjectVersions and DeleteObjects.
func (aw *AWSAdmin) EmptyBucket(ctx context.Context, bucketName string) error {
	aw.Log.Info().Str("bucket", bucketName).Msg("Emptying S3 bucket")

	var keyMarker *string
	var versionMarker *string

	for {
		req := &s3.ListObjectVersionsInput{Bucket: &bucketName}
		if keyMarker != nil {
			req.KeyMarker = keyMarker
		}
		if versionMarker != nil {
			req.VersionIdMarker = versionMarker
		}

		page, err := aw.S3.ListObjectVersions(ctx, req)
		if err != nil {
			aw.Log.Error().Err(err).Str("bucket", bucketName).Msg("Failed to list object versions")
			return err
		}

		var toDelete []s3types.ObjectIdentifier
		for _, v := range page.Versions {
			toDelete = append(toDelete, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
		}
		for _, d := range page.DeleteMarkers {
			toDelete = append(toDelete, s3types.ObjectIdentifier{Key: d.Key, VersionId: d.VersionId})
		}

		if len(toDelete) > 0 {
			_, err := aw.S3.DeleteObjects(ctx, &s3.DeleteObjectsInput{
				Bucket: &bucketName,
				Delete: &s3types.Delete{Objects: toDelete},
			})
			if err != nil {
				aw.Log.Error().Err(err).Str("bucket", bucketName).Msg("Failed to delete objects")
				return err
			}
		}

		// Continue if next markers present
		if page.NextKeyMarker != nil && *page.NextKeyMarker != "" {
			keyMarker = page.NextKeyMarker
			versionMarker = page.NextVersionIdMarker
			continue
		}
		if page.NextVersionIdMarker != nil && *page.NextVersionIdMarker != "" {
			keyMarker = page.NextKeyMarker
			versionMarker = page.NextVersionIdMarker
			continue
		}
		break
	}

	aw.Log.Info().Str("bucket", bucketName).Msg("Bucket emptied")
	return nil
}

// DeleteBucketCompletely empties then deletes the bucket.
func (aw *AWSAdmin) DeleteBucketCompletely(ctx context.Context, bucketName string) error {
	if err := aw.EmptyBucket(ctx, bucketName); err != nil {
		return err
	}
	aw.Log.Info().Str("bucket", bucketName).Msg("Deleting S3 bucket")
	_, err := aw.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucketName})
	if err != nil {
		aw.Log.Error().Err(err).Str("bucket", bucketName).Msg("Failed to delete bucket")
		return err
	}
	aw.Log.Info().Str("bucket", bucketName).Msg("Bucket deleted")
	return nil
}

// ListAllStandardBuckets returns buckets whose names start with "psb-".
func (aw *AWSAdmin) ListAllStandardBuckets(ctx context.Context) ([]s3types.Bucket, error) {
	out, err := aw.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}
	var filtered []s3types.Bucket
	for _, b := range out.Buckets {
		if b.Name != nil && strings.HasPrefix(*b.Name, "psb-") {
			arn := "arn:aws:s3:::" + *b.Name
			b.BucketArn = &arn
			filtered = append(filtered, b)
		}
	}
	return filtered, nil
}

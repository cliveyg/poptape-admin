package awsutil

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/rs/zerolog"
	"os"
	"strings"
)

type AWSAdmin struct {
	IAM *iam.Client
	S3  *s3.Client
	Log *zerolog.Logger
}

//-----------------------------------------------------------------------------
// ListAllPoptapeStandardBuckets
//-----------------------------------------------------------------------------

func NewAWSAdmin(ctx context.Context, logger *zerolog.Logger) (*AWSAdmin, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("AWS config error")
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}
	return &AWSAdmin{
		IAM: iam.NewFromConfig(cfg),
		S3:  s3.NewFromConfig(cfg),
		Log: logger,
	}, nil
}

//-----------------------------------------------------------------------------
// ListAllPoptapeStandardBuckets
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) TestConnection(ctx context.Context) error {

	if aw.IAM == nil || aw.S3 == nil {
		return fmt.Errorf("AWSAdmin not properly initialised")
	}

	usrs, err := aw.IAM.ListUsers(ctx, &iam.ListUsersInput{MaxItems: aws.Int32(1)})
	if err != nil {
		aw.Log.Error().Err(err).Msg("IAM connection test failed")
		return fmt.Errorf("IAM connection test failed: %w", err)
	}

	// Test S3: List buckets
	var bucks *s3.ListBucketsOutput
	bucks, err = aw.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		aw.Log.Error().Err(err).Msg("S3 connection test failed")
		return fmt.Errorf("S3 connection test failed: %w", err)
	}

	if os.Getenv("ENVIRONMENT") == "DEV" {
		for _, user := range usrs.Users {
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
		for _, bcks := range bucks.Buckets {
			bname := ""
			if bcks.Name != nil {
				bname = *bcks.Name
			}
			// S3 bucket struct in AWS SDK v2 does NOT have BucketArn field
			// Instead, construct the ARN yourself
			arn := fmt.Sprintf("arn:aws:s3:::%s", bname)
			aw.Log.Debug().Msgf("Bucket name [%s], ARN [%s] Created [%s]", bname, arn, bcks.CreationDate)
		}
	}

	return nil
}

// --- IAM User Management ---

//-----------------------------------------------------------------------------
// CreateUserWithAccessKey
//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
// DeleteUserCompletely
// Deletes an IAM user and all associated resources (access keys, policies, etc.)
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) DeleteUserCompletely(ctx context.Context, userName string) error {
	aw.Log.Info().Str("user", userName).Msg("Deleting IAM user and all attached resources")

	// delete access keys
	keys, _ := aw.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &userName})
	for _, ak := range keys.AccessKeyMetadata {
		_, err := aw.IAM.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: &userName, AccessKeyId: ak.AccessKeyId})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("accessKeyId", *ak.AccessKeyId).Msg("Failed to delete access key")
		}
	}

	// delete inline policies
	pols, _ := aw.IAM.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &userName})
	for _, pol := range pols.PolicyNames {
		_, err := aw.IAM.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: &userName, PolicyName: &pol})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("policy", pol).Msg("Failed to delete inline policy")
		}
	}

	// detach managed policies
	mpols, _ := aw.IAM.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &userName})
	for _, mp := range mpols.AttachedPolicies {
		_, err := aw.IAM.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: &userName, PolicyArn: mp.PolicyArn})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("policyArn", *mp.PolicyArn).Msg("Failed to detach managed policy")
		}
	}

	// remove from groups
	grps, _ := aw.IAM.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: &userName})
	for _, grp := range grps.Groups {
		_, err := aw.IAM.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{UserName: &userName, GroupName: grp.GroupName})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("group", *grp.GroupName).Msg("Failed to remove user from group")
		}
	}

	// delete login profile
	_, _ = aw.IAM.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{UserName: &userName})

	// delete signing certificates
	certs, _ := aw.IAM.ListSigningCertificates(ctx, &iam.ListSigningCertificatesInput{UserName: &userName})
	for _, cert := range certs.Certificates {
		_, err := aw.IAM.DeleteSigningCertificate(ctx, &iam.DeleteSigningCertificateInput{UserName: &userName, CertificateId: cert.CertificateId})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("certID", *cert.CertificateId).Msg("Failed to delete signing certificate")
		}
	}

	// deactivate and delete MFA devices
	mfas, _ := aw.IAM.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &userName})
	for _, mfa := range mfas.MFADevices {
		_, _ = aw.IAM.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: &userName, SerialNumber: mfa.SerialNumber})
		_, _ = aw.IAM.DeleteVirtualMFADevice(ctx, &iam.DeleteVirtualMFADeviceInput{SerialNumber: mfa.SerialNumber})
	}

	// delete SSH public keys
	sshkeys, _ := aw.IAM.ListSSHPublicKeys(ctx, &iam.ListSSHPublicKeysInput{UserName: &userName})
	for _, key := range sshkeys.SSHPublicKeys {
		_, err := aw.IAM.DeleteSSHPublicKey(ctx, &iam.DeleteSSHPublicKeyInput{UserName: &userName, SSHPublicKeyId: key.SSHPublicKeyId})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("sshKeyId", *key.SSHPublicKeyId).Msg("Failed to delete SSH public key")
		}
	}

	// delete service-specific credentials
	sscs, _ := aw.IAM.ListServiceSpecificCredentials(ctx, &iam.ListServiceSpecificCredentialsInput{UserName: &userName})
	for _, cred := range sscs.ServiceSpecificCredentials {
		_, err := aw.IAM.DeleteServiceSpecificCredential(ctx, &iam.DeleteServiceSpecificCredentialInput{UserName: &userName, ServiceSpecificCredentialId: cred.ServiceSpecificCredentialId})
		if err != nil {
			aw.Log.Error().Err(err).Str("user", userName).Str("serviceCredId", *cred.ServiceSpecificCredentialId).Msg("Failed to delete service-specific credential")
		}
	}

	// finally, delete the user
	_, err := aw.IAM.DeleteUser(ctx, &iam.DeleteUserInput{UserName: &userName})
	if err != nil {
		aw.Log.Error().Err(err).Str("user", userName).Msg("Failed to delete IAM user")
		return err
	}
	aw.Log.Info().Str("user", userName).Msg("Deleted IAM user successfully")
	return nil
}

//-----------------------------------------------------------------------------
// ListAllUsers
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) ListAllUsers(ctx context.Context) ([]iamtypes.User, error) {
	if aw.IAM == nil {
		return nil, fmt.Errorf("AWSAdmin.IAM is nil")
	}

	var users []iamtypes.User
	input := &iam.ListUsersInput{}
	paginator := iam.NewListUsersPaginator(aw.IAM, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}
		users = append(users, page.Users...)
	}
	return users, nil
}

// --- S3 Bucket Management ---

//-----------------------------------------------------------------------------
// CreateBucket
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) CreateBucket(ctx context.Context, bucketName string) error {
	aw.Log.Info().Str("bucket", bucketName).Msg("Creating S3 bucket")
	_, err := aw.S3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucketName})
	return err
}

//-----------------------------------------------------------------------------
// EmptyBucket - deletes all objects (and versions, if versioned) in the bucket
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) EmptyBucket(ctx context.Context, bucketName string) error {

	aw.Log.Info().Str("bucket", bucketName).Msg("Emptying S3 bucket")
	p := s3.NewListObjectVersionsPaginator(aw.S3, &s3.ListObjectVersionsInput{Bucket: &bucketName})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
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
	}
	aw.Log.Info().Str("bucket", bucketName).Msg("Bucket emptied")
	return nil
}

//-----------------------------------------------------------------------------
// DeleteBucketCompletely - empties and then deletes an S3 bucket
//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
// ListAllStandardBuckets
//-----------------------------------------------------------------------------

func (aw *AWSAdmin) ListAllStandardBuckets(ctx context.Context) ([]s3types.Bucket, error) {
	if aw.S3 == nil {
		return nil, fmt.Errorf("AWSAdmin.S3 is nil")
	}
	out, err := aw.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}
	var filtered []s3types.Bucket
	for _, b := range out.Buckets {
		if b.Name != nil && strings.HasPrefix(*b.Name, "psb-") {
			*b.BucketArn = "arn:aws:s3:::" + *b.Name
			filtered = append(filtered, b)
		}
	}
	return filtered, nil
}

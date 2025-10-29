package testutils

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"sync"
)

// FakeIAM implements IAMAPI for unit tests.
type FakeIAM struct {
	mu sync.Mutex

	CreateUserErr      error
	CreateAccessKeyErr error

	AccessKeys                 map[string][]iamtypes.AccessKeyMetadata
	UserPolicies               map[string][]string
	AttachedPolicies           map[string][]iamtypes.AttachedPolicy
	GroupsForUser              map[string][]iamtypes.Group
	SigningCertificates        map[string][]iamtypes.SigningCertificate
	MFADevices                 map[string][]iamtypes.MFADevice
	SSHPublicKeys              map[string][]iamtypes.SSHPublicKeyMetadata
	ServiceSpecificCredentials map[string][]iamtypes.ServiceSpecificCredentialMetadata

	DeleteAccessKeyErr                 error
	DeleteUserPolicyErr                error
	DetachUserPolicyErr                error
	RemoveUserFromGroupErr             error
	DeleteSigningCertificateErr        error
	DeactivateMFADeviceErr             error
	DeleteVirtualMFADeviceErr          error
	DeleteSSHPublicKeyErr              error
	DeleteServiceSpecificCredentialErr error
	DeleteUserErr                      error

	DeletedAccessKeys        []struct{ User, AccessKeyId string }
	DeletedUserPolicies      []struct{ User, PolicyName string }
	DetachedUserPolicies     []struct{ User, PolicyArn string }
	RemovedFromGroups        []struct{ User, GroupName string }
	DeletedSigningCerts      []struct{ User, CertID string }
	DeactivatedMFADevices    []struct{ User, Serial string }
	DeletedVirtualMFADevices []struct{ Serial string }
	DeletedSSHPublicKeys     []struct{ User, KeyID string }
	DeletedServiceCreds      []struct{ User, ID string }
	DeleteUserCalledFor      []string
}

func (f *FakeIAM) ensureMaps() {
	if f.AccessKeys == nil {
		f.AccessKeys = map[string][]iamtypes.AccessKeyMetadata{}
	}
	if f.UserPolicies == nil {
		f.UserPolicies = map[string][]string{}
	}
	if f.AttachedPolicies == nil {
		f.AttachedPolicies = map[string][]iamtypes.AttachedPolicy{}
	}
	if f.GroupsForUser == nil {
		f.GroupsForUser = map[string][]iamtypes.Group{}
	}
	if f.SigningCertificates == nil {
		f.SigningCertificates = map[string][]iamtypes.SigningCertificate{}
	}
	if f.MFADevices == nil {
		f.MFADevices = map[string][]iamtypes.MFADevice{}
	}
	if f.SSHPublicKeys == nil {
		f.SSHPublicKeys = map[string][]iamtypes.SSHPublicKeyMetadata{}
	}
	if f.ServiceSpecificCredentials == nil {
		f.ServiceSpecificCredentials = map[string][]iamtypes.ServiceSpecificCredentialMetadata{}
	}
}

func (f *FakeIAM) CreateUser(ctx context.Context, in *iam.CreateUserInput, optFns ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	_ = optFns
	if f.CreateUserErr != nil {
		return nil, f.CreateUserErr
	}
	return &iam.CreateUserOutput{}, nil
}

func (f *FakeIAM) CreateAccessKey(ctx context.Context, in *iam.CreateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	_ = optFns
	if f.CreateAccessKeyErr != nil {
		return nil, f.CreateAccessKeyErr
	}
	return &iam.CreateAccessKeyOutput{
		AccessKey: &iamtypes.AccessKey{
			AccessKeyId:     aws.String("FAKEAKID"),
			SecretAccessKey: aws.String("FAKESECRET"),
		},
	}, nil
}

func (f *FakeIAM) ListUsers(ctx context.Context, in *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	_ = optFns
	return &iam.ListUsersOutput{
		Users:       []iamtypes.User{},
		IsTruncated: false,
	}, nil
}

func (f *FakeIAM) ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	meta := f.AccessKeys[user]
	if meta == nil {
		meta = []iamtypes.AccessKeyMetadata{}
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: meta}, nil
}

func (f *FakeIAM) DeleteAccessKey(ctx context.Context, in *iam.DeleteAccessKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	akid := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.AccessKeyId != nil {
			akid = *in.AccessKeyId
		}
	}
	f.DeletedAccessKeys = append(f.DeletedAccessKeys, struct{ User, AccessKeyId string }{User: user, AccessKeyId: akid})
	if f.DeleteAccessKeyErr != nil {
		return nil, f.DeleteAccessKeyErr
	}
	if arr, ok := f.AccessKeys[user]; ok {
		newArr := make([]iamtypes.AccessKeyMetadata, 0, len(arr))
		for _, a := range arr {
			if a.AccessKeyId == nil || *a.AccessKeyId != akid {
				newArr = append(newArr, a)
			}
		}
		f.AccessKeys[user] = newArr
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (f *FakeIAM) ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListUserPoliciesOutput{PolicyNames: f.UserPolicies[user]}, nil
}

func (f *FakeIAM) DeleteUserPolicy(ctx context.Context, in *iam.DeleteUserPolicyInput, optFns ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	pname := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.PolicyName != nil {
			pname = *in.PolicyName
		}
	}
	f.DeletedUserPolicies = append(f.DeletedUserPolicies, struct{ User, PolicyName string }{User: user, PolicyName: pname})
	if f.DeleteUserPolicyErr != nil {
		return nil, f.DeleteUserPolicyErr
	}
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (f *FakeIAM) ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.AttachedPolicies[user]}, nil
}

func (f *FakeIAM) DetachUserPolicy(ctx context.Context, in *iam.DetachUserPolicyInput, optFns ...func(*iam.Options)) (*iam.DetachUserPolicyOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	arn := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.PolicyArn != nil {
			arn = *in.PolicyArn
		}
	}
	f.DetachedUserPolicies = append(f.DetachedUserPolicies, struct{ User, PolicyArn string }{User: user, PolicyArn: arn})
	if f.DetachUserPolicyErr != nil {
		return nil, f.DetachUserPolicyErr
	}
	return &iam.DetachUserPolicyOutput{}, nil
}

func (f *FakeIAM) ListGroupsForUser(ctx context.Context, in *iam.ListGroupsForUserInput, optFns ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListGroupsForUserOutput{Groups: f.GroupsForUser[user]}, nil
}

func (f *FakeIAM) RemoveUserFromGroup(ctx context.Context, in *iam.RemoveUserFromGroupInput, optFns ...func(*iam.Options)) (*iam.RemoveUserFromGroupOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	group := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.GroupName != nil {
			group = *in.GroupName
		}
	}
	f.RemovedFromGroups = append(f.RemovedFromGroups, struct{ User, GroupName string }{User: user, GroupName: group})
	if f.RemoveUserFromGroupErr != nil {
		return nil, f.RemoveUserFromGroupErr
	}
	return &iam.RemoveUserFromGroupOutput{}, nil
}

func (f *FakeIAM) DeleteLoginProfile(ctx context.Context, in *iam.DeleteLoginProfileInput, optFns ...func(*iam.Options)) (*iam.DeleteLoginProfileOutput, error) {
	_ = optFns
	return &iam.DeleteLoginProfileOutput{}, nil
}

func (f *FakeIAM) ListSigningCertificates(ctx context.Context, in *iam.ListSigningCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListSigningCertificatesOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListSigningCertificatesOutput{Certificates: f.SigningCertificates[user]}, nil
}

func (f *FakeIAM) DeleteSigningCertificate(ctx context.Context, in *iam.DeleteSigningCertificateInput, optFns ...func(*iam.Options)) (*iam.DeleteSigningCertificateOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	cid := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.CertificateId != nil {
			cid = *in.CertificateId
		}
	}
	f.DeletedSigningCerts = append(f.DeletedSigningCerts, struct{ User, CertID string }{User: user, CertID: cid})
	if f.DeleteSigningCertificateErr != nil {
		return nil, f.DeleteSigningCertificateErr
	}
	return &iam.DeleteSigningCertificateOutput{}, nil
}

func (f *FakeIAM) ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListMFADevicesOutput{MFADevices: f.MFADevices[user]}, nil
}

func (f *FakeIAM) DeactivateMFADevice(ctx context.Context, in *iam.DeactivateMFADeviceInput, optFns ...func(*iam.Options)) (*iam.DeactivateMFADeviceOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	serial := ""
	user := ""
	if in != nil {
		if in.SerialNumber != nil {
			serial = *in.SerialNumber
		}
		if in.UserName != nil {
			user = *in.UserName
		}
	}
	f.DeactivatedMFADevices = append(f.DeactivatedMFADevices, struct{ User, Serial string }{User: user, Serial: serial})
	if f.DeactivateMFADeviceErr != nil {
		return nil, f.DeactivateMFADeviceErr
	}
	return &iam.DeactivateMFADeviceOutput{}, nil
}

func (f *FakeIAM) DeleteVirtualMFADevice(ctx context.Context, in *iam.DeleteVirtualMFADeviceInput, optFns ...func(*iam.Options)) (*iam.DeleteVirtualMFADeviceOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	serial := ""
	if in != nil && in.SerialNumber != nil {
		serial = *in.SerialNumber
	}
	f.DeletedVirtualMFADevices = append(f.DeletedVirtualMFADevices, struct{ Serial string }{Serial: serial})
	if f.DeleteVirtualMFADeviceErr != nil {
		return nil, f.DeleteVirtualMFADeviceErr
	}
	return &iam.DeleteVirtualMFADeviceOutput{}, nil
}

func (f *FakeIAM) ListSSHPublicKeys(ctx context.Context, in *iam.ListSSHPublicKeysInput, optFns ...func(*iam.Options)) (*iam.ListSSHPublicKeysOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListSSHPublicKeysOutput{SSHPublicKeys: f.SSHPublicKeys[user]}, nil
}

func (f *FakeIAM) DeleteSSHPublicKey(ctx context.Context, in *iam.DeleteSSHPublicKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteSSHPublicKeyOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	keyid := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.SSHPublicKeyId != nil {
			keyid = *in.SSHPublicKeyId
		}
	}
	f.DeletedSSHPublicKeys = append(f.DeletedSSHPublicKeys, struct{ User, KeyID string }{User: user, KeyID: keyid})
	if f.DeleteSSHPublicKeyErr != nil {
		return nil, f.DeleteSSHPublicKeyErr
	}
	return &iam.DeleteSSHPublicKeyOutput{}, nil
}

func (f *FakeIAM) ListServiceSpecificCredentials(ctx context.Context, in *iam.ListServiceSpecificCredentialsInput, optFns ...func(*iam.Options)) (*iam.ListServiceSpecificCredentialsOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureMaps()
	user := ""
	if in != nil && in.UserName != nil {
		user = *in.UserName
	}
	return &iam.ListServiceSpecificCredentialsOutput{ServiceSpecificCredentials: f.ServiceSpecificCredentials[user]}, nil
}

func (f *FakeIAM) DeleteServiceSpecificCredential(ctx context.Context, in *iam.DeleteServiceSpecificCredentialInput, optFns ...func(*iam.Options)) (*iam.DeleteServiceSpecificCredentialOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	user := ""
	id := ""
	if in != nil {
		if in.UserName != nil {
			user = *in.UserName
		}
		if in.ServiceSpecificCredentialId != nil {
			id = *in.ServiceSpecificCredentialId
		}
	}
	f.DeletedServiceCreds = append(f.DeletedServiceCreds, struct{ User, ID string }{User: user, ID: id})
	if f.DeleteServiceSpecificCredentialErr != nil {
		return nil, f.DeleteServiceSpecificCredentialErr
	}
	return &iam.DeleteServiceSpecificCredentialOutput{}, nil
}

func (f *FakeIAM) DeleteUser(ctx context.Context, in *iam.DeleteUserInput, optFns ...func(*iam.Options)) (*iam.DeleteUserOutput, error) {
	_ = optFns
	f.mu.Lock()
	defer f.mu.Unlock()
	name := ""
	if in != nil && in.UserName != nil {
		name = *in.UserName
	}
	f.DeleteUserCalledFor = append(f.DeleteUserCalledFor, name)
	if f.DeleteUserErr != nil {
		return nil, f.DeleteUserErr
	}
	return &iam.DeleteUserOutput{}, nil
}

// ------------------------------------
// FakeS3 implements S3API for unit tests.
// ------------------------------------

type FakeS3 struct {
	mu sync.Mutex

	// For simulating ListObjectVersions responses
	ListObjectVersionsOutputs []*s3.ListObjectVersionsOutput
	ListObjectVersionsErrs    []error
	ListObjectVersionsCalls   int

	// For simulating DeleteObjects responses
	DeleteObjectsInputs []*s3.DeleteObjectsInput
	DeleteObjectsErrs   []error
	DeleteObjectsCalls  int

	// For simulating DeleteBucket responses
	DeleteBucketErr   error
	DeleteBucketCalls int
}

func (f *FakeS3) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{}, nil
}

func (f *FakeS3) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	return &s3.CreateBucketOutput{}, nil
}

func (f *FakeS3) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DeleteBucketCalls++
	if f.DeleteBucketErr != nil {
		return nil, f.DeleteBucketErr
	}
	return &s3.DeleteBucketOutput{}, nil
}

func (f *FakeS3) ListObjectVersions(ctx context.Context, params *s3.ListObjectVersionsInput, optFns ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	call := f.ListObjectVersionsCalls
	f.ListObjectVersionsCalls++
	if call < len(f.ListObjectVersionsOutputs) {
		return f.ListObjectVersionsOutputs[call], f.ListObjectVersionsErrs[call]
	}
	return &s3.ListObjectVersionsOutput{}, nil
}

func (f *FakeS3) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.DeleteObjectsCalls
	f.DeleteObjectsCalls++
	f.DeleteObjectsInputs = append(f.DeleteObjectsInputs, params)
	if call < len(f.DeleteObjectsErrs) {
		return &s3.DeleteObjectsOutput{}, f.DeleteObjectsErrs[call]
	}
	return &s3.DeleteObjectsOutput{}, nil
}

// Constructor for convenience in tests
func NewFakeS3() *FakeS3 {
	return &FakeS3{
		ListObjectVersionsOutputs: []*s3.ListObjectVersionsOutput{},
		ListObjectVersionsErrs:    []error{},
		DeleteObjectsInputs:       []*s3.DeleteObjectsInput{},
		DeleteObjectsErrs:         []error{},
	}
}

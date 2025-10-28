package testutils

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Minimal, self-contained FakeIAM used by unit tests for DeleteUserCompletely
// and CreateUserWithAccessKey. ListUsers returns IsTruncated: false (bool).
type FakeIAM struct {
	mu sync.Mutex

	// Error fields needed for aws_create_user_test.go
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

	// Optional errors to simulate failures for DeleteUserCompletely tests
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

	// Recorded operations for assertions
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

// CreateUser returns error if CreateUserErr is set.
func (f *FakeIAM) CreateUser(ctx context.Context, in *iam.CreateUserInput, optFns ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	_ = optFns
	if f.CreateUserErr != nil {
		return nil, f.CreateUserErr
	}
	return &iam.CreateUserOutput{}, nil
}

// CreateAccessKey returns error if CreateAccessKeyErr is set.
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

// ListUsers - returns IsTruncated: false (type bool) for compatibility with your tests.
func (f *FakeIAM) ListUsers(ctx context.Context, in *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	_ = optFns
	return &iam.ListUsersOutput{
		Users:       []iamtypes.User{},
		IsTruncated: false, // <-- THIS IS THE FIX
	}, nil
}

// ListAccessKeys returns configured access keys for the provided user.
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

// DeleteAccessKey records invocation and returns configured error if any.
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
	// remove from configured list if present
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

// ListUserPolicies returns configured inline policy names.
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

// DeleteUserPolicy records the deletion and may return configured error.
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

// ListAttachedUserPolicies returns configured attached policies.
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

// DetachUserPolicy records the detach and may return configured error.
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

// ListGroupsForUser returns configured groups for the user.
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

// RemoveUserFromGroup records the removal and may return configured error.
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

// DeleteLoginProfile - stub.
func (f *FakeIAM) DeleteLoginProfile(ctx context.Context, in *iam.DeleteLoginProfileInput, optFns ...func(*iam.Options)) (*iam.DeleteLoginProfileOutput, error) {
	_ = optFns
	return &iam.DeleteLoginProfileOutput{}, nil
}

// ListSigningCertificates returns configured certificates.
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

// DeleteSigningCertificate records and may return configured error.
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

// ListMFADevices returns configured MFA devices for a user.
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

// DeactivateMFADevice records the deactivation and may return configured error.
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

// DeleteVirtualMFADevice records the deletion and may return configured error.
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

// ListSSHPublicKeys returns configured SSH public keys for a user.
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

// DeleteSSHPublicKey records the deletion and may return configured error.
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

// ListServiceSpecificCredentials returns configured service-specific credentials for a user.
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

// DeleteServiceSpecificCredential records the deletion and may return configured error.
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

// DeleteUser records invocation and may return configured error.
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

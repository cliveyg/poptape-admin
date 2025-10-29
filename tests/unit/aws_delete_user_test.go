package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

// Unit tests for DeleteUserCompletely in delete_user2.go (NO "2" in test names)

func TestDeleteUserCompletely_HappyPath(t *testing.T) {
	logger := testutils.SetupLogger()
	fake := &testutils.FakeIAM{}

	user := "alice"

	fake.AccessKeys = map[string][]types.AccessKeyMetadata{
		user: {
			{AccessKeyId: aws.String("AKIA1")},
			{AccessKeyId: aws.String("AKIA2")},
		},
	}
	fake.UserPolicies = map[string][]string{
		user: {"policy1", "policy2"},
	}
	fake.AttachedPolicies = map[string][]types.AttachedPolicy{
		user: {
			{PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnly")},
		},
	}
	fake.GroupsForUser = map[string][]types.Group{
		user: {
			{GroupName: aws.String("devs")},
		},
	}
	fake.SigningCertificates = map[string][]types.SigningCertificate{
		user: {
			{CertificateId: aws.String("cert1")},
		},
	}
	fake.MFADevices = map[string][]types.MFADevice{
		user: {
			{SerialNumber: aws.String("mfaserial")},
		},
	}
	fake.SSHPublicKeys = map[string][]types.SSHPublicKeyMetadata{
		user: {
			{SSHPublicKeyId: aws.String("ssh1")},
		},
	}
	fake.ServiceSpecificCredentials = map[string][]types.ServiceSpecificCredentialMetadata{
		user: {
			{ServiceSpecificCredentialId: aws.String("svc1")},
		},
	}

	aw := &awsutil.AWSAdmin{IAM: fake, S3: nil, Log: logger}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := aw.DeleteUserCompletely(ctx, user)
	require.NoError(t, err)

	require.Contains(t, fake.DeleteUserCalledFor, user)
	require.Len(t, fake.DeletedAccessKeys, 2)
	require.Equal(t, "AKIA1", fake.DeletedAccessKeys[0].AccessKeyId)
	require.Equal(t, "AKIA2", fake.DeletedAccessKeys[1].AccessKeyId)

	require.Len(t, fake.DeletedUserPolicies, 2)
	foundPol1 := false
	foundPol2 := false
	for _, p := range fake.DeletedUserPolicies {
		if p.PolicyName == "policy1" {
			foundPol1 = true
		}
		if p.PolicyName == "policy2" {
			foundPol2 = true
		}
	}
	require.True(t, foundPol1 && foundPol2)

	require.Len(t, fake.DetachedUserPolicies, 1)
	require.Equal(t, "arn:aws:iam::aws:policy/ReadOnly", fake.DetachedUserPolicies[0].PolicyArn)

	require.Len(t, fake.RemovedFromGroups, 1)
	require.Equal(t, "devs", fake.RemovedFromGroups[0].GroupName)

	require.Len(t, fake.DeletedSigningCerts, 1)
	require.Equal(t, "cert1", fake.DeletedSigningCerts[0].CertID)

	require.Len(t, fake.DeactivatedMFADevices, 1)
	require.Equal(t, "mfaserial", fake.DeactivatedMFADevices[0].Serial)
	require.Len(t, fake.DeletedVirtualMFADevices, 1)
	require.Equal(t, "mfaserial", fake.DeletedVirtualMFADevices[0].Serial)

	require.Len(t, fake.DeletedSSHPublicKeys, 1)
	require.Equal(t, "ssh1", fake.DeletedSSHPublicKeys[0].KeyID)

	require.Len(t, fake.DeletedServiceCreds, 1)
	require.Equal(t, "svc1", fake.DeletedServiceCreds[0].ID)
}

func TestDeleteUserCompletely_NoResources(t *testing.T) {
	logger := testutils.SetupLogger()
	fake := &testutils.FakeIAM{}
	user := "emptyuser"

	aw := &awsutil.AWSAdmin{IAM: fake, S3: nil, Log: logger}

	err := aw.DeleteUserCompletely(context.Background(), user)
	require.NoError(t, err)
	require.Len(t, fake.DeleteUserCalledFor, 1)
	require.Equal(t, user, fake.DeleteUserCalledFor[0])
}

func TestDeleteUserCompletely_DeleteUserFails(t *testing.T) {
	logger := testutils.SetupLogger()
	fake := &testutils.FakeIAM{}
	user := "bob"

	fake.DeleteUserErr = errors.New("cannot delete user")
	aw := &awsutil.AWSAdmin{IAM: fake, S3: nil, Log: logger}

	err := aw.DeleteUserCompletely(context.Background(), user)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot delete user")
	require.Len(t, fake.DeleteUserCalledFor, 1)
	require.Equal(t, user, fake.DeleteUserCalledFor[0])
}

func TestDeleteUserCompletely_DeleteAccessKeyFailsButContinues(t *testing.T) {
	logger := testutils.SetupLogger()
	fake := &testutils.FakeIAM{}
	user := "charlie"

	fake.AccessKeys = map[string][]types.AccessKeyMetadata{
		user: {
			{AccessKeyId: aws.String("AKIA-FAIL")},
		},
	}
	fake.DeleteAccessKeyErr = errors.New("delete access key failed")

	aw := &awsutil.AWSAdmin{IAM: fake, S3: nil, Log: logger}

	err := aw.DeleteUserCompletely(context.Background(), user)
	require.NoError(t, err)
	require.Len(t, fake.DeletedAccessKeys, 1)
	require.Equal(t, "AKIA-FAIL", fake.DeletedAccessKeys[0].AccessKeyId)
	require.Len(t, fake.DeleteUserCalledFor, 1)
	require.Equal(t, user, fake.DeleteUserCalledFor[0])
}

package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

// Unit tests contain no helper functions or types; they use testutils fakes.

func TestCreateUserWithAccessKey_Success(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeIAM := &testutils.FakeIAM{}
	aw := &awsutil.AWSAdmin{IAM: fakeIAM, S3: nil, Log: logger}

	ak, err := aw.CreateUserWithAccessKey(context.Background(), "unit-test-user")
	require.NoError(t, err)
	require.NotNil(t, ak)
	require.Equal(t, "FAKEAKID", *ak.AccessKeyId)
	require.Equal(t, "FAKESECRET", *ak.SecretAccessKey)
}

func TestCreateUserWithAccessKey_CreateUserFails(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeIAM := &testutils.FakeIAM{CreateUserErr: errors.New("create user failed")}
	aw := &awsutil.AWSAdmin{IAM: fakeIAM, S3: nil, Log: logger}

	ak, err := aw.CreateUserWithAccessKey(context.Background(), "unit-test-user")
	require.Error(t, err)
	require.Nil(t, ak)
}

func TestCreateUserWithAccessKey_CreateAccessKeyFails(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeIAM := &testutils.FakeIAM{CreateAccessKeyErr: errors.New("create access key failed")}
	aw := &awsutil.AWSAdmin{IAM: fakeIAM, S3: nil, Log: logger}

	ak, err := aw.CreateUserWithAccessKey(context.Background(), "unit-test-user")
	require.Error(t, err)
	require.Nil(t, ak)
}

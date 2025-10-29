package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func TestDeleteBucketCompletely_HappyPath(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()

	// Simulate successful empty and delete
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions:            nil,
			DeleteMarkers:       nil,
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil}
	fakeS3.DeleteObjectsErrs = []error{nil}
	fakeS3.DeleteBucketErr = nil // Add this field to FakeS3 if not present

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.DeleteBucketCompletely(context.Background(), "bucketname")
	require.NoError(t, err)
	require.Equal(t, 1, fakeS3.ListObjectVersionsCalls)
	require.Equal(t, 1, fakeS3.DeleteBucketCalls)
}

func TestDeleteBucketCompletely_EmptyBucketFails(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()

	// Simulate error from EmptyBucket
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{nil}
	fakeS3.ListObjectVersionsErrs = []error{errors.New("empty error")}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.DeleteBucketCompletely(context.Background(), "bucketname")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty error")
	// Bucket deletion should not proceed
	require.Equal(t, 0, fakeS3.DeleteBucketCalls)
}

func TestDeleteBucketCompletely_DeleteBucketFails(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()

	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions:            nil,
			DeleteMarkers:       nil,
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil}
	fakeS3.DeleteObjectsErrs = []error{nil}
	fakeS3.DeleteBucketErr = errors.New("delete error") // Add this field to FakeS3 if not present

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.DeleteBucketCompletely(context.Background(), "bucketname")
	require.Error(t, err)
	require.Contains(t, err.Error(), "delete error")
	require.Equal(t, 1, fakeS3.DeleteBucketCalls)
}

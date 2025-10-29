package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cliveyg/poptape-admin/awsutil"
	"github.com/cliveyg/poptape-admin/testutils"
	"github.com/stretchr/testify/require"
)

func TestEmptyBucket_HappyPath(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions: []s3types.ObjectVersion{
				{Key: aws.String("foo.txt"), VersionId: aws.String("v1")},
				{Key: aws.String("bar.txt"), VersionId: aws.String("v2")},
			},
			DeleteMarkers: []s3types.DeleteMarkerEntry{
				{Key: aws.String("baz.txt"), VersionId: aws.String("v3")},
			},
			NextKeyMarker:       aws.String("next"),
			NextVersionIdMarker: aws.String("nextver"),
		},
		{
			Versions:            []s3types.ObjectVersion{},
			DeleteMarkers:       []s3types.DeleteMarkerEntry{},
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil, nil}
	fakeS3.DeleteObjectsErrs = []error{nil}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.EmptyBucket(context.Background(), "bucketname")
	require.NoError(t, err)

	require.Equal(t, 2, fakeS3.ListObjectVersionsCalls)
	require.Equal(t, 1, fakeS3.DeleteObjectsCalls)

	require.Len(t, fakeS3.DeleteObjectsInputs, 1)
	input := fakeS3.DeleteObjectsInputs[0]
	require.Equal(t, "bucketname", *input.Bucket)
	require.Len(t, input.Delete.Objects, 3)
	keys := []string{
		aws.ToString(input.Delete.Objects[0].Key),
		aws.ToString(input.Delete.Objects[1].Key),
		aws.ToString(input.Delete.Objects[2].Key),
	}
	require.ElementsMatch(t, keys, []string{"foo.txt", "bar.txt", "baz.txt"})
}

func TestEmptyBucket_NoObjectsToDelete(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions:            []s3types.ObjectVersion{},
			DeleteMarkers:       []s3types.DeleteMarkerEntry{},
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.EmptyBucket(context.Background(), "nobucket")
	require.NoError(t, err)
	require.Equal(t, 1, fakeS3.ListObjectVersionsCalls)
	require.Equal(t, 0, fakeS3.DeleteObjectsCalls)
}

func TestEmptyBucket_Pagination(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions: []s3types.ObjectVersion{
				{Key: aws.String("foo.txt"), VersionId: aws.String("v1")},
			},
			DeleteMarkers:       []s3types.DeleteMarkerEntry{},
			NextKeyMarker:       aws.String("nextkey"),
			NextVersionIdMarker: aws.String("nextver"),
		},
		{
			Versions: []s3types.ObjectVersion{
				{Key: aws.String("bar.txt"), VersionId: aws.String("v2")},
			},
			DeleteMarkers:       []s3types.DeleteMarkerEntry{},
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil, nil}
	fakeS3.DeleteObjectsErrs = []error{nil, nil}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.EmptyBucket(context.Background(), "bucketpag")
	require.NoError(t, err)
	require.Equal(t, 2, fakeS3.ListObjectVersionsCalls)
	require.Equal(t, 2, fakeS3.DeleteObjectsCalls)

	require.Len(t, fakeS3.DeleteObjectsInputs, 2)
	input1 := fakeS3.DeleteObjectsInputs[0]
	require.Equal(t, "bucketpag", *input1.Bucket)
	require.Len(t, input1.Delete.Objects, 1)
	require.Equal(t, "foo.txt", aws.ToString(input1.Delete.Objects[0].Key))

	input2 := fakeS3.DeleteObjectsInputs[1]
	require.Len(t, input2.Delete.Objects, 1)
	require.Equal(t, "bar.txt", aws.ToString(input2.Delete.Objects[0].Key))
}

func TestEmptyBucket_ListObjectVersionsError(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{nil}
	fakeS3.ListObjectVersionsErrs = []error{errors.New("failed to list versions")}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.EmptyBucket(context.Background(), "bucketerr")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to list versions")
}

func TestEmptyBucket_DeleteObjectsError(t *testing.T) {
	logger := testutils.SetupLogger()
	fakeS3 := testutils.NewFakeS3()
	fakeS3.ListObjectVersionsOutputs = []*s3.ListObjectVersionsOutput{
		{
			Versions: []s3types.ObjectVersion{
				{Key: aws.String("foo.txt"), VersionId: aws.String("v1")},
			},
			DeleteMarkers:       []s3types.DeleteMarkerEntry{},
			NextKeyMarker:       nil,
			NextVersionIdMarker: nil,
		},
	}
	fakeS3.ListObjectVersionsErrs = []error{nil}
	fakeS3.DeleteObjectsErrs = []error{errors.New("delete objects failed")}

	aw := &awsutil.AWSAdmin{IAM: nil, S3: fakeS3, Log: logger}
	err := aw.EmptyBucket(context.Background(), "bucketdelerr")
	require.Error(t, err)
	require.Contains(t, err.Error(), "delete objects failed")
	require.Equal(t, 1, fakeS3.DeleteObjectsCalls)
}

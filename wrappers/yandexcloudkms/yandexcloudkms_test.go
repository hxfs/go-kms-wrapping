package yandexcloudkms

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	"google.golang.org/grpc"
)

func TestYandexCloudKmsWrapper(t *testing.T) {
	wrapper := NewWrapper()
	if err := wrapper.setClient(&mockSymmetricCryptoServiceClient{primaryVersionID: "version-id"}); err != nil {
		t.Fatal(err)
	}

	if _, err := wrapper.SetConfig(nil); err == nil {
		t.Fatal("expected error when Yandex.Cloud key ID is not provided")
	}

	// Set the key
	if err := os.Setenv(EnvYandexCloudKmsKeyId, "key-id"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvYandexCloudKmsKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := wrapper.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestYandexCloudKmsWrapper_Lifecycle(t *testing.T) {
	wrapper := NewWrapper()
	if err := wrapper.setClient(&mockSymmetricCryptoServiceClient{primaryVersionID: "version-id"}); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(EnvYandexCloudKmsKeyId, "key-id"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvYandexCloudKmsKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := wrapper.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Test Encrypt and Decrypt calls
	plaintext := []byte("foo")
	encryptedBlobInfo, err := wrapper.Encrypt(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	decrypted, err := wrapper.Decrypt(context.Background(), encryptedBlobInfo)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	if !reflect.DeepEqual(decrypted, plaintext) {
		t.Fatalf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestYandexCloudKmsWrapper_KeyRotation(t *testing.T) {
	versionID1 := "version-id-1"
	versionID2 := "version-id-2"

	wrapper := NewWrapper()
	client := &mockSymmetricCryptoServiceClient{primaryVersionID: versionID1}
	if err := wrapper.setClient(client); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(EnvYandexCloudKmsKeyId, "key-id"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Unsetenv(EnvYandexCloudKmsKeyId); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := wrapper.SetConfig(context.Background()); err != nil {
		t.Fatal(err)
	}

	keyId, err := wrapper.KeyId(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keyId, versionID1) {
		t.Fatalf("expected %s, got %s", versionID1, keyId)
	}

	client.rotateKey(versionID2)
	keyId, err = wrapper.KeyId(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keyId, versionID1) {
		t.Fatalf("expected %s, got %s", versionID1, keyId)
	}

	// Only Encrypt calls update wrapper.currentVersionID
	if _, err := wrapper.Encrypt(context.Background(), []byte("plaintext")); err != nil {
		t.Fatal(err)
	}
	keyId, err = wrapper.KeyId(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keyId, versionID2) {
		t.Fatalf("expected %s, got %s", versionID2, keyId)
	}
}

// Mock implementation of kms.SymmetricCryptoServiceClient
type mockSymmetricCryptoServiceClient struct {
	primaryVersionID string
}

func (m *mockSymmetricCryptoServiceClient) Encrypt(_ context.Context, in *kms.SymmetricEncryptRequest, _ ...grpc.CallOption) (*kms.SymmetricEncryptResponse, error) {
	encoded := base64.StdEncoding.EncodeToString(in.Plaintext)

	return &kms.SymmetricEncryptResponse{
		KeyId:      in.KeyId,
		VersionId:  m.primaryVersionID,
		Ciphertext: []byte(encoded),
	}, nil
}

func (m *mockSymmetricCryptoServiceClient) Decrypt(_ context.Context, in *kms.SymmetricDecryptRequest, _ ...grpc.CallOption) (*kms.SymmetricDecryptResponse, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(in.Ciphertext))
	if err != nil {
		return nil, err
	}

	return &kms.SymmetricDecryptResponse{
		KeyId:     in.KeyId,
		VersionId: m.primaryVersionID,
		Plaintext: decoded,
	}, nil
}

func (m *mockSymmetricCryptoServiceClient) ReEncrypt(_ context.Context, _ *kms.SymmetricReEncryptRequest, _ ...grpc.CallOption) (*kms.SymmetricReEncryptResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSymmetricCryptoServiceClient) GenerateDataKey(_ context.Context, _ *kms.GenerateDataKeyRequest, _ ...grpc.CallOption) (*kms.GenerateDataKeyResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSymmetricCryptoServiceClient) rotateKey(primaryVersionID string) {
	m.primaryVersionID = primaryVersionID
}

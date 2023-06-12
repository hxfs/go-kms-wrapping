package ukms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	wrapping "github.com/hxfs/go-kms-wrapping/v2"

	"github.com/ucloud/ucloud-sdk-go/ucloud"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvUCloudKmsWrapperKeyId   = "UCLOUDKMS_WRAPPER_KEY_ID"
	EnvVaultUCloudKmsSealKeyId = "VAULT_UCLOUDKMS_SEAL_KEY_ID"
)

// Wrapper is a Wrapper that uses AliCloud's KMS
type Wrapper struct {
	client       kmsClient
	domain       string
	projectId    string
	keyId        string
	currentKeyId *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new AliCloud Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the AliCloudKMSWrapper object based on
// values from the config parameter.
//
// Order of precedence AliCloud values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvUCloudKmsWrapperKeyId) != "":
		k.keyId = os.Getenv(EnvUCloudKmsWrapperKeyId)
	case os.Getenv(EnvVaultUCloudKmsSealKeyId) != "":
		k.keyId = os.Getenv(EnvVaultUCloudKmsSealKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("key id not found (env or config) for ucloud kms wrapper configuration")
	}

	region := ""
	if k.client == nil {
		cfg := ucloud.NewConfig()
		cfg.ProjectId = opts.withProjectId
		cfg.Region = "undefined"
		cfg.BaseUrl = "https://api.ucloud.cn"

		auth := auth.NewCredential()
		auth.PrivateKey = opts.withSecretKey
		auth.PublicKey = opts.withAccessKey

		client := getUcloudKmsClient(&cfg, &auth)
		k.client = client
	}

	// Test the client connection using provided key ID

	keyInfo, err := k.client.describeKey(k.keyId)
	if err != nil {
		return nil, fmt.Errorf("error fetching AliCloud KMS key information: %w", err)
	}
	if keyInfo == "" {
		return nil, errors.New("no key information returned")
	}

	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(k.keyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = region
	wrapConfig.Metadata["kms_key_id"] = k.keyId
	if k.domain != "" {
		wrapConfig.Metadata["domain"] = k.domain
	}

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeAliCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the ucloud ukms.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	Plaintext := base64.StdEncoding.EncodeToString(env.Key)

	output, err := k.client.encrypt(k.keyId, Plaintext)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id.

	k.currentKeyId.Store(k.keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyId,
			WrappedKey: []byte(output),
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	// KeyId is not passed to this call because AliCloud handles this
	// internally based on the metadata stored with the encrypted data

	ciphertextBlob := string(in.KeyInfo.WrappedKey)

	output, err := k.client.decrypt(ciphertextBlob)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

type kmsClient interface {
	describeKey(keyID string) (string, error)
	encrypt(keyID, plainText string) (string, error)
	decrypt(cipherText string) (string, error)
}

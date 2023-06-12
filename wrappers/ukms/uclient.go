package ukms

import (
	"errors"

	"github.com/ucloud/ucloud-sdk-go/ucloud"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
	"github.com/ucloud/ucloud-sdk-go/ucloud/config"
)

type KMSClient struct {
	client *ucloud.Client
}

func getUcloudKmsClient(cfg *config.Config, cred *auth.Credential) *KMSClient {
	client := ucloud.NewClient(cfg, cred)
	return &KMSClient{client: client}
}

func (c *KMSClient) decrypt(cipherText string) (string, error) {
	req := c.client.NewGenericRequest()
	err := req.SetPayload(map[string]interface{}{
		"Action":         "Decrypt",
		"CiphertextBlob": cipherText,
	})
	if err != nil {
		return "", nil
	}

	resp, err := c.client.GenericInvoke(req)
	if err != nil {
		return "", err
	}

	py, ok := resp.GetPayload()
	val, ok := py["Plaintext"]
	if !ok {
		return "", errors.New("not found")
	}
	return val.(string), nil

	return "", nil
}

func (c *KMSClient) describeKey(keyID string) (string, error) {
	req := c.client.NewGenericRequest()
	err := req.SetPayload(map[string]interface{}{
		"Action": "DescribeKey",
		"KeyId":  keyID,
	})

	if err != nil {
		return "", err
	}

	resp, err := c.client.GenericInvoke(req)
	if err != nil {
		return "", err
	}

	py := resp.GetPayload()

	val, ok := py["KeyId"]
	if !ok {
		return "", errors.New("not found")
	}
	return val.(string), nil
}

func (c *KMSClient) encrypt(keyID, plainText string) (string, error) {
	req := c.client.NewGenericRequest()
	err := req.SetPayload(map[string]interface{}{
		"Action":    "Encrypt",
		"KeyId":     keyID,
		"Plaintext": plainText,
	})

	if err != nil {
		return "", err
	}

	resp, err := c.client.GenericInvoke(req)
	if err != nil {
		return "", err
	}

	py := resp.GetPayload()

	val, ok := py["KeyId"]
	if !ok {
		return "", errors.New("not found")
	}
	return val.(string), nil
}

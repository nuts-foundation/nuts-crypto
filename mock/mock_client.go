// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/client.go

// Package mock is a generated GoMock package.
package mock

import (
	crypto "crypto"
	gomock "github.com/golang/mock/gomock"
	jwk "github.com/lestrrat-go/jwx/jwk"
	pkg "github.com/nuts-foundation/nuts-crypto/pkg"
	types "github.com/nuts-foundation/nuts-crypto/pkg/types"
	reflect "reflect"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// DecryptKeyAndCipherTextFor mocks base method
func (m *MockClient) DecryptKeyAndCipherTextFor(cipherText types.DoubleEncryptedCipherText, legalEntity types.LegalEntity) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecryptKeyAndCipherTextFor", cipherText, legalEntity)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptKeyAndCipherTextFor indicates an expected call of DecryptKeyAndCipherTextFor
func (mr *MockClientMockRecorder) DecryptKeyAndCipherTextFor(cipherText, legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptKeyAndCipherTextFor", reflect.TypeOf((*MockClient)(nil).DecryptKeyAndCipherTextFor), cipherText, legalEntity)
}

// EncryptKeyAndPlainTextWith mocks base method
func (m *MockClient) EncryptKeyAndPlainTextWith(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncryptKeyAndPlainTextWith", plainText, keys)
	ret0, _ := ret[0].(types.DoubleEncryptedCipherText)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptKeyAndPlainTextWith indicates an expected call of EncryptKeyAndPlainTextWith
func (mr *MockClientMockRecorder) EncryptKeyAndPlainTextWith(plainText, keys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptKeyAndPlainTextWith", reflect.TypeOf((*MockClient)(nil).EncryptKeyAndPlainTextWith), plainText, keys)
}

// ExternalIdFor mocks base method
func (m *MockClient) ExternalIdFor(subject, actor string, entity types.LegalEntity) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExternalIdFor", subject, actor, entity)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExternalIdFor indicates an expected call of ExternalIdFor
func (mr *MockClientMockRecorder) ExternalIdFor(subject, actor, entity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExternalIdFor", reflect.TypeOf((*MockClient)(nil).ExternalIdFor), subject, actor, entity)
}

// GenerateKeyPairFor mocks base method
func (m *MockClient) GenerateKeyPairFor(legalEntity types.LegalEntity) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateKeyPairFor", legalEntity)
	ret0, _ := ret[0].(error)
	return ret0
}

// GenerateKeyPairFor indicates an expected call of GenerateKeyPairFor
func (mr *MockClientMockRecorder) GenerateKeyPairFor(legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateKeyPairFor", reflect.TypeOf((*MockClient)(nil).GenerateKeyPairFor), legalEntity)
}

// SignFor mocks base method
func (m *MockClient) SignFor(data []byte, legalEntity types.LegalEntity) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignFor", data, legalEntity)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignFor indicates an expected call of SignFor
func (mr *MockClientMockRecorder) SignFor(data, legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignFor", reflect.TypeOf((*MockClient)(nil).SignFor), data, legalEntity)
}

// SignCertificate mocks base method
func (m *MockClient) SignCertificate(entity, ca types.LegalEntity, pkcs10 []byte, profile pkg.CertificateProfile) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignCertificate", entity, ca, pkcs10, profile)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignCertificate indicates an expected call of SignCertificate
func (mr *MockClientMockRecorder) SignCertificate(entity, ca, pkcs10, profile interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignCertificate", reflect.TypeOf((*MockClient)(nil).SignCertificate), entity, ca, pkcs10, profile)
}

// GetOpaquePrivateKey mocks base method
func (m *MockClient) GetOpaquePrivateKey(entity types.LegalEntity) (crypto.Signer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOpaquePrivateKey", entity)
	ret0, _ := ret[0].(crypto.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOpaquePrivateKey indicates an expected call of GetOpaquePrivateKey
func (mr *MockClientMockRecorder) GetOpaquePrivateKey(entity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOpaquePrivateKey", reflect.TypeOf((*MockClient)(nil).GetOpaquePrivateKey), entity)
}

// VerifyWith mocks base method
func (m *MockClient) VerifyWith(data, sig []byte, jwk jwk.Key) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyWith", data, sig, jwk)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyWith indicates an expected call of VerifyWith
func (mr *MockClientMockRecorder) VerifyWith(data, sig, jwk interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyWith", reflect.TypeOf((*MockClient)(nil).VerifyWith), data, sig, jwk)
}

// PublicKeyInPEM mocks base method
func (m *MockClient) PublicKeyInPEM(legalEntity types.LegalEntity) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicKeyInPEM", legalEntity)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PublicKeyInPEM indicates an expected call of PublicKeyInPEM
func (mr *MockClientMockRecorder) PublicKeyInPEM(legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicKeyInPEM", reflect.TypeOf((*MockClient)(nil).PublicKeyInPEM), legalEntity)
}

// PublicKeyInJWK mocks base method
func (m *MockClient) PublicKeyInJWK(legalEntity types.LegalEntity) (jwk.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicKeyInJWK", legalEntity)
	ret0, _ := ret[0].(jwk.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PublicKeyInJWK indicates an expected call of PublicKeyInJWK
func (mr *MockClientMockRecorder) PublicKeyInJWK(legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicKeyInJWK", reflect.TypeOf((*MockClient)(nil).PublicKeyInJWK), legalEntity)
}

// SignJwtFor mocks base method
func (m *MockClient) SignJwtFor(claims map[string]interface{}, legalEntity types.LegalEntity) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJwtFor", claims, legalEntity)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJwtFor indicates an expected call of SignJwtFor
func (mr *MockClientMockRecorder) SignJwtFor(claims, legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJwtFor", reflect.TypeOf((*MockClient)(nil).SignJwtFor), claims, legalEntity)
}

// KeyExistsFor mocks base method
func (m *MockClient) KeyExistsFor(legalEntity types.LegalEntity) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "KeyExistsFor", legalEntity)
	ret0, _ := ret[0].(bool)
	return ret0
}

// KeyExistsFor indicates an expected call of KeyExistsFor
func (mr *MockClientMockRecorder) KeyExistsFor(legalEntity interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KeyExistsFor", reflect.TypeOf((*MockClient)(nil).KeyExistsFor), legalEntity)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/client.go

// Package mock is a generated GoMock package.
package mock

import (
	crypto "crypto"
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	jwk "github.com/lestrrat-go/jwx/jwk"
	pkg "github.com/nuts-foundation/nuts-crypto/pkg"
	cert "github.com/nuts-foundation/nuts-crypto/pkg/cert"
	types "github.com/nuts-foundation/nuts-crypto/pkg/types"
	reflect "reflect"
	time "time"
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

// DecryptKeyAndCipherText mocks base method
func (m *MockClient) DecryptKeyAndCipherText(cipherText types.DoubleEncryptedCipherText, key types.KeyIdentifier) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecryptKeyAndCipherText", cipherText, key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecryptKeyAndCipherText indicates an expected call of DecryptKeyAndCipherText
func (mr *MockClientMockRecorder) DecryptKeyAndCipherText(cipherText, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptKeyAndCipherText", reflect.TypeOf((*MockClient)(nil).DecryptKeyAndCipherText), cipherText, key)
}

// EncryptKeyAndPlainText mocks base method
func (m *MockClient) EncryptKeyAndPlainText(plainText []byte, keys []jwk.Key) (types.DoubleEncryptedCipherText, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EncryptKeyAndPlainText", plainText, keys)
	ret0, _ := ret[0].(types.DoubleEncryptedCipherText)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EncryptKeyAndPlainText indicates an expected call of EncryptKeyAndPlainText
func (mr *MockClientMockRecorder) EncryptKeyAndPlainText(plainText, keys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptKeyAndPlainText", reflect.TypeOf((*MockClient)(nil).EncryptKeyAndPlainText), plainText, keys)
}

// CalculateExternalId mocks base method
func (m *MockClient) CalculateExternalId(subject, actor string, key types.KeyIdentifier) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CalculateExternalId", subject, actor, key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CalculateExternalId indicates an expected call of CalculateExternalId
func (mr *MockClientMockRecorder) CalculateExternalId(subject, actor, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CalculateExternalId", reflect.TypeOf((*MockClient)(nil).CalculateExternalId), subject, actor, key)
}

// GenerateKeyPair mocks base method
func (m *MockClient) GenerateKeyPair(key types.KeyIdentifier) (crypto.PublicKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateKeyPair", key)
	ret0, _ := ret[0].(crypto.PublicKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateKeyPair indicates an expected call of GenerateKeyPair
func (mr *MockClientMockRecorder) GenerateKeyPair(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateKeyPair", reflect.TypeOf((*MockClient)(nil).GenerateKeyPair), key)
}

// Sign mocks base method
func (m *MockClient) Sign(data []byte, key types.KeyIdentifier) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", data, key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign
func (mr *MockClientMockRecorder) Sign(data, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockClient)(nil).Sign), data, key)
}

// SignCertificate mocks base method
func (m *MockClient) SignCertificate(subjectKey, caKey types.KeyIdentifier, pkcs10 []byte, profile pkg.CertificateProfile) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignCertificate", subjectKey, caKey, pkcs10, profile)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignCertificate indicates an expected call of SignCertificate
func (mr *MockClientMockRecorder) SignCertificate(subjectKey, caKey, pkcs10, profile interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignCertificate", reflect.TypeOf((*MockClient)(nil).SignCertificate), subjectKey, caKey, pkcs10, profile)
}

// GetPrivateKey mocks base method
func (m *MockClient) GetPrivateKey(key types.KeyIdentifier) (crypto.Signer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrivateKey", key)
	ret0, _ := ret[0].(crypto.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPrivateKey indicates an expected call of GetPrivateKey
func (mr *MockClientMockRecorder) GetPrivateKey(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrivateKey", reflect.TypeOf((*MockClient)(nil).GetPrivateKey), key)
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

// GetTLSCertificate mocks base method
func (m *MockClient) GetTLSCertificate(caKey types.KeyIdentifier) (*x509.Certificate, crypto.PrivateKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTLSCertificate", caKey)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(crypto.PrivateKey)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetTLSCertificate indicates an expected call of GetTLSCertificate
func (mr *MockClientMockRecorder) GetTLSCertificate(caKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTLSCertificate", reflect.TypeOf((*MockClient)(nil).GetTLSCertificate), caKey)
}

// GetPublicKeyAsPEM mocks base method
func (m *MockClient) GetPublicKeyAsPEM(key types.KeyIdentifier) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPublicKeyAsPEM", key)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKeyAsPEM indicates an expected call of GetPublicKeyAsPEM
func (mr *MockClientMockRecorder) GetPublicKeyAsPEM(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKeyAsPEM", reflect.TypeOf((*MockClient)(nil).GetPublicKeyAsPEM), key)
}

// GetPublicKeyAsJWK mocks base method
func (m *MockClient) GetPublicKeyAsJWK(key types.KeyIdentifier) (jwk.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPublicKeyAsJWK", key)
	ret0, _ := ret[0].(jwk.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKeyAsJWK indicates an expected call of GetPublicKeyAsJWK
func (mr *MockClientMockRecorder) GetPublicKeyAsJWK(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKeyAsJWK", reflect.TypeOf((*MockClient)(nil).GetPublicKeyAsJWK), key)
}

// SignJWT mocks base method
func (m *MockClient) SignJWT(claims map[string]interface{}, key types.KeyIdentifier) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWT", claims, key)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWT indicates an expected call of SignJWT
func (mr *MockClientMockRecorder) SignJWT(claims, key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWT", reflect.TypeOf((*MockClient)(nil).SignJWT), claims, key)
}

// SignJWSEphemeral mocks base method
func (m *MockClient) SignJWSEphemeral(payload []byte, caKey types.KeyIdentifier, csr x509.CertificateRequest, signingTime time.Time) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignJWSEphemeral", payload, caKey, csr, signingTime)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignJWSEphemeral indicates an expected call of SignJWSEphemeral
func (mr *MockClientMockRecorder) SignJWSEphemeral(payload, caKey, csr, signingTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignJWSEphemeral", reflect.TypeOf((*MockClient)(nil).SignJWSEphemeral), payload, caKey, csr, signingTime)
}

// VerifyJWS mocks base method
func (m *MockClient) VerifyJWS(signature []byte, signingTime time.Time, certVerifier cert.Verifier) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyJWS", signature, signingTime, certVerifier)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyJWS indicates an expected call of VerifyJWS
func (mr *MockClientMockRecorder) VerifyJWS(signature, signingTime, certVerifier interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyJWS", reflect.TypeOf((*MockClient)(nil).VerifyJWS), signature, signingTime, certVerifier)
}

// PrivateKeyExists mocks base method
func (m *MockClient) PrivateKeyExists(key types.KeyIdentifier) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateKeyExists", key)
	ret0, _ := ret[0].(bool)
	return ret0
}

// PrivateKeyExists indicates an expected call of PrivateKeyExists
func (mr *MockClientMockRecorder) PrivateKeyExists(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateKeyExists", reflect.TypeOf((*MockClient)(nil).PrivateKeyExists), key)
}

// TrustStore mocks base method
func (m *MockClient) TrustStore() cert.TrustStore {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TrustStore")
	ret0, _ := ret[0].(cert.TrustStore)
	return ret0
}

// TrustStore indicates an expected call of TrustStore
func (mr *MockClientMockRecorder) TrustStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TrustStore", reflect.TypeOf((*MockClient)(nil).TrustStore))
}
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// Receipt represents a cryptographic payment receipt
type Receipt struct {
	ID        string         `json:"id"`
	Version   string         `json:"version"`
	Timestamp time.Time      `json:"timestamp"`
	Payment   PaymentDetails `json:"payment"`
	Service   ServiceDetails `json:"service"`
}

// PaymentDetails contains payment-related information
type PaymentDetails struct {
	Payer      string  `json:"payer"`
	Recipient  string  `json:"recipient"`
	Amount     string  `json:"amount"`
	Token      string  `json:"token"`
	ChainID    int64   `json:"chainId"`
	ChainIDs   []int64 `json:"supportedChainIds"` // Advertises multi-chain capability
	Nonce      string  `json:"nonce"`
}

// ServiceDetails contains service-related information
type ServiceDetails struct {
	Endpoint     string `json:"endpoint"`
	RequestHash  string `json:"request_hash"`
	ResponseHash string `json:"response_hash"`
}

// SignedReceipt contains the receipt and its cryptographic signature
type SignedReceipt struct {
	Receipt         Receipt `json:"receipt"`
	Signature       string  `json:"signature"`
	ServerPublicKey string  `json:"server_public_key"`
}

type ReceiptStore interface {
	Store(ctx context.Context, receipt *SignedReceipt, ttl time.Duration) error
	Get(ctx context.Context, id string) (*SignedReceipt, bool, error)
	CleanupExpired(ctx context.Context) error
	Close() error
}

// GenerateReceipt creates a new receipt for a successful payment, 
// wiring in the global SupportedChainIDs registry.
func GenerateReceipt(payment PaymentContext, payer string, endpoint string, reqBody, respBody []byte) (*SignedReceipt, error) {
	receiptID, err := generateReceiptID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate receipt ID: %w", err)
	}

	receipt := Receipt{
		ID:        receiptID,
		Version:   "1.0",
		Timestamp: time.Now().UTC(),
		Payment: PaymentDetails{
			Payer:     payer,
			Recipient: payment.Recipient,
			Amount:    payment.Amount,
			Token:     payment.Token,
			ChainID:   payment.ChainID,
			ChainIDs:  SupportedChainIDs, // Inject multi-chain registry
			Nonce:     payment.Nonce,
		},
		Service: ServiceDetails{
			Endpoint:     endpoint,
			RequestHash:  hashData(reqBody),
			ResponseHash: hashData(respBody),
		},
	}

	return signReceipt(receipt)
}

// generateReceiptID generates a unique receipt ID with "rcpt_" prefix
func generateReceiptID() (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random receipt ID: %w", err)
	}
	return "rcpt_" + hex.EncodeToString(bytes), nil
}

// hashData computes SHA-256 hash of data and returns hex-encoded string
func hashData(data []byte) string {
	if len(data) == 0 {
		return "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// signReceipt signs a receipt using the server's private key
func signReceipt(receipt Receipt) (*SignedReceipt, error) {
	privateKey, err := getServerPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load server private key: %w", err)
	}

	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal receipt: %w", err)
	}

	hash := crypto.Keccak256Hash(receiptBytes)
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign receipt: %w", err)
	}

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKey)

	return &SignedReceipt{
		Receipt:         receipt,
		Signature:       "0x" + hex.EncodeToString(signature),
		ServerPublicKey: "0x" + hex.EncodeToString(publicKeyBytes),
	}, nil
}

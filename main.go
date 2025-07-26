package main

import (
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

type Wallet struct {
	Mnemonic string
	Address  string
}

func NewWallet() (*Wallet, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, _ := btcec.PrivKeyFromBytes(seed[:32])

	wif, err := btcutil.NewWIF(masterKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, err
	}

	address, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		Mnemonic: mnemonic,
		Address:  address.EncodeAddress(),
	}, nil
}

func RecoverWallet(mnemonic string) (*Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, _ := btcec.PrivKeyFromBytes(seed[:32])

	wif, err := btcutil.NewWIF(masterKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, err
	}

	address, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		Mnemonic: mnemonic,
		Address:  address.EncodeAddress(),
	}, nil
}

func main() {
	wallet, err := NewWallet()
	if err != nil {
		panic(err)
	}

	fmt.Println("Mnemonic:", wallet.Mnemonic)
	fmt.Println("Address:", wallet.Address)
}

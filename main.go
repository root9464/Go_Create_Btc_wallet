package main

import (
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip39"
)

func NewWallet() (string, string, *btcec.PrivateKey, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", nil, err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", "", nil, err
	}

	seed := bip39.NewSeed(mnemonic, "")
	privKey, _ := btcec.PrivKeyFromBytes(seed[:32])

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return "", "", nil, err
	}

	address, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return "", "", nil, err
	}

	return mnemonic, address.EncodeAddress(), privKey, nil
}

func CreateAndSignTx(privKey *btcec.PrivateKey, fromAddress, toAddress string, amount int64, prevTxID string, prevOutIndex uint32) (*wire.MsgTx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	recipientAddr, err := btcutil.DecodeAddress(toAddress, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	recipientScript, err := txscript.PayToAddrScript(recipientAddr)
	if err != nil {
		return nil, err
	}

	tx.AddTxOut(wire.NewTxOut(amount, recipientScript))

	hash, err := chainhash.NewHashFromStr(prevTxID)
	if err != nil {
		return nil, err
	}

	txIn := wire.NewTxIn(wire.NewOutPoint(hash, prevOutIndex), nil, nil)
	tx.AddTxIn(txIn)

	senderAddr, err := btcutil.DecodeAddress(fromAddress, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	byres, _ := txscript.PayToAddrScript(senderAddr)

	sigScript, err := txscript.SignatureScript(
		tx,
		0,
		byres,
		txscript.SigHashAll,
		privKey,
		true,
	)
	if err != nil {
		return nil, err
	}

	tx.TxIn[0].SignatureScript = sigScript

	vm, err := txscript.NewEngine(
		byres,
		tx,
		0,
		txscript.StandardVerifyFlags,
		nil,
		nil,
		0,
		nil,
	)
	if err != nil {
		return nil, err
	}

	if err := vm.Execute(); err != nil {
		return nil, err
	}

	return tx, nil
}

func ValidateWallet(mnemonic, address string) error {
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid mnemonic phrase")
	}

	seed := bip39.NewSeed(mnemonic, "")
	privKey, _ := btcec.PrivKeyFromBytes(seed[:32])

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return fmt.Errorf("failed to create WIF: %v", err)
	}

	derivedAddress, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("failed to derive address: %v", err)
	}

	if derivedAddress.EncodeAddress() != address {
		return fmt.Errorf("address does not match mnemonic")
	}

	_, err = btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return fmt.Errorf("invalid address format: %v", err)
	}

	return nil
}

func main() {
	mnemonic, address, _, err := NewWallet()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Mnemonic:", mnemonic)
	fmt.Println("Address:", address)
	err = ValidateWallet(mnemonic, address)
	if err != nil {
		fmt.Println("Wallet validation failed:", err)
		return
	}

	fmt.Println("Wallet validated successfully")
}

// слав это чтобы проверить транзу, создать транзу, подписать ее но не отправлять в сеть бтк
// func main() {
// 	mnemonic, address, privKey, err := generateMnemonicAndAddress()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	fmt.Println("Mnemonic:", mnemonic)
// 	fmt.Println("Address:", address)

// 	recipient := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
// 	amount := int64(100000)
// 	prevTxID := "0000000000000000000000000000000000000000000000000000000000000000"
// 	prevOutIndex := uint32(0)

// 	tx, err := createAndSignTx(privKey, address, recipient, amount, prevTxID, prevOutIndex)
// 	if err != nil {
// 		fmt.Println("Error signing transaction:", err)
// 		return
// 	}

// 	fmt.Println("Transaction signed successfully")
// 	fmt.Printf("TxID: %s\n", tx.TxHash().String())
// }

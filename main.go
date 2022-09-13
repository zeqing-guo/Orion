package main

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

type Resp struct {
	Difficulty      string `json:"difficulty"`
	TotalDifficulty string `json:"totalDifficulty"`
}

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		logrus.WithError(err).Fatal("init: load .env")
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGQUIT)
	go func() {
		<-signalCh
		logrus.Println("waiting for program to quit")
		cancel()
	}()

	msg := os.Getenv("MESSAGE")
	if len(msg) == 0 {
		logrus.Fatal("void message")
	}

	privKeyBytes, err := os.ReadFile(os.Getenv("PRIV_KEY_PATH"))
	if err != nil {
		logrus.Fatal(err)
	}
	privKey, err := crypto.HexToECDSA(string(privKeyBytes))
	if err != nil {
		logrus.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	logrus.Printf("address: %s", addr.String())

	wsClient, err := rpc.DialWebsocket(ctx, os.Getenv("WS_ENDPOINT"), "")
	if err != nil {
		logrus.WithError(err).Fatal("main: init rpc")
	}
	headers := make(chan *types.Header)
	headerSub, err := wsClient.EthSubscribe(ctx, headers, "newHeads")
	if err != nil {
		logrus.Fatal(err)
	}
	client := ethclient.NewClient(wsClient)

	terminalDifficulty, successfully := new(big.Int).SetString("58750000000000000000000", 0)
	if !successfully {
		logrus.Fatal("main: setString terminalDifficulty")
	}
	for {
		select {
		case <-ctx.Done():
			headerSub.Unsubscribe()
			return
		case err = <-headerSub.Err():
			logrus.WithError(err).Fatal("main: sub get an err")
		case h := <-headers:
			logrus.Infof("get header #%s", h.Number.String())
			var result Resp
			err = wsClient.CallContext(ctx, &result, "eth_getBlockByNumber", "latest", false)
			if err != nil {
				logrus.WithError(err).Error("main: call context")
				continue
			}
			if willMergeAtNextBlock(&result, terminalDifficulty) {
				txHash, err := sendMsg(ctx, client, msg, privKey, addr)
				if err != nil {
					logrus.WithError(err).Error("main: sendMsg")
				} else {
					if checkTxStatus(ctx, client, txHash) {
						logrus.WithField("tx", txHash.Hex()).Info("tx confirmed")
						return
					}
				}
			}
		}
	}
}

func checkTxStatus(ctx context.Context, client *ethclient.Client, txHash common.Hash) bool {
	// loop for 15 seconds
	for i := 0; i < 30; i++ {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err != nil {
			logrus.WithError(err).Error("checkTxStatus: transaction receipt")
			time.Sleep(time.Second)
			continue
		}
		blockHeader, err := client.HeaderByNumber(ctx, receipt.BlockNumber)
		if err != nil {
			logrus.WithError(err).Error("checkTxStatus: headerByNumber")
			return false
		}
		// difficulty will be 0 after the merge
		if blockHeader.Difficulty.Cmp(big.NewInt(0)) == 0 {
			return true
		}
	}
	return false
}

func sendMsg(ctx context.Context, client *ethclient.Client, msg string, privKey *ecdsa.PrivateKey, addr common.Address) (txHash common.Hash, err error) {
	nonce, err := client.NonceAt(ctx, addr, nil)
	if err != nil {
		logrus.WithError(err).Error("sendMsg: get nonce")
		return
	}

	gasTipCap := big.NewInt(100000000000)
	gasFeeCap := big.NewInt(1000000000000)

	tx := types.NewTx(
		&types.DynamicFeeTx{
			Nonce:     nonce,
			Gas:       100000,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Data:      []byte(msg),
			To:        &addr,
		},
	)
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(1)), privKey)
	if err != nil {
		logrus.WithError(err).Error("sendMsg: sign tx")
		return
	}

	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		logrus.WithError(err).Error("sendMsg: send transaction")
		return
	}
	return signedTx.Hash(), nil
}

func willMergeAtNextBlock(resp *Resp, terminalDifficulty *big.Int) bool {
	delta := big.NewInt(100000000000000)
	totalDifficulty, successfully := new(big.Int).SetString(resp.TotalDifficulty, 0)
	if !successfully {
		logrus.Error("willMergeAtNextBlock: setString totalDifficulty")
		return false
	}
	difficulty, successfully := new(big.Int).SetString(resp.Difficulty, 0)
	if !successfully {
		logrus.Error("willMergeAtNextBlock: setString difficulty")
		return false
	}
	logrus.WithFields(logrus.Fields{
		"diff":     difficulty.String(),
		"td":       totalDifficulty.String(),
		"terminal": terminalDifficulty.String(),
	}).Info("get diff and td")

	if difficulty.Cmp(big.NewInt(0)) == 0 {
		logrus.Info("merged")
		return true
	}

	totalDifficulty.Add(totalDifficulty, difficulty)
	totalDifficulty.Add(totalDifficulty, delta)

	return terminalDifficulty.Cmp(totalDifficulty) <= 0
}

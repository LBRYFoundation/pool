// Copyright (c) 2015-2026 YiiMP / LBRY Pool
//
// WebSocket blocknotify daemon for lbcd (https://github.com/lbryfoundation/lbcd).
// Connects directly to lbcd's WebSocket RPC endpoint (`ws`), listens for
// blockconnected notifications, computes the 112-byte LBRY block header double-SHA256
// block hash, and invokes the `blocknotify` binary to notify the LBRY Stratum server.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/btcsuite/btcd/rpcclient"
)

// computeLbryBlockHash computes the double-SHA256 block hash (reversed to big-endian hex)
// of a serialized 112-byte LBRY block header.
func computeLbryBlockHash(header []byte) string {
	if len(header) > 112 {
		header = header[:112]
	}
	first := sha256.Sum256(header)
	second := sha256.Sum256(first[:])

	// Reverse bytes to standard big-endian display order
	for i, j := 0, len(second)-1; i < j; i, j = i+1, j-1 {
		second[i], second[j] = second[j], second[i]
	}
	return hex.EncodeToString(second[:])
}

func main() {
	var (
		processName = flag.String("bin", "blocknotify", "Path to blocknotify executable")
		stratumDest = flag.String("stratum", "127.0.0.1:3334", "Stratum host:port")
		coinID      = flag.String("coinid", "1", "LBC database coin ID")
		lbcdHost    = flag.String("host", "127.0.0.1:9245", "lbcd RPC host:port")
		lbcdUser    = flag.String("user", "lbcdrpc", "lbcd RPC username")
		lbcdPass    = flag.String("pass", "", "lbcd RPC password")
		certFile    = flag.String("cert", "rpc.cert", "Path to lbcd TLS rpc.cert")
		debug       = flag.Bool("debug", false, "Enable verbose logging")
	)
	flag.Parse()

	ntfnHandlers := rpcclient.NotificationHandlers{
		OnBlockConnected: func(blockHeader []byte, transactions [][]byte) {
			if len(blockHeader) < 112 {
				log.Printf("ignoring short block header (%d bytes)", len(blockHeader))
				return
			}
			blockHash := computeLbryBlockHash(blockHeader)
			args := []string{*stratumDest, *coinID, blockHash}
			out, err := exec.Command(*processName, args...).Output()
			if err != nil {
				log.Printf("blocknotify error: %v", err)
			} else if *debug && len(out) > 0 {
				log.Printf("blocknotify output: %s", out)
			}
			if *debug {
				log.Printf("LBC block connected: %s", blockHash)
			}
		},
	}

	certs, err := os.ReadFile(filepath.Clean(*certFile))
	if err != nil {
		certs = nil
		log.Printf("%v, connecting without TLS...", err)
	}

	connCfg := &rpcclient.ConnConfig{
		Host:         *lbcdHost,
		Endpoint:     "ws",
		User:         *lbcdUser,
		Pass:         *lbcdPass,
		DisableTLS:   certs == nil,
		Certificates: certs,
	}

	client, err := rpcclient.New(connCfg, &ntfnHandlers)
	if err != nil {
		log.Fatalln(err)
	}

	if err := client.NotifyBlocks(); err != nil {
		log.Fatalln(err)
	}
	log.Println("lbcd NotifyBlocks: registration complete")

	client.WaitForShutdown()
}

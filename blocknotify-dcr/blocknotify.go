// Copyright (c) 2015-2026 YiiMP / LBRY Pool
//
// WebSocket blocknotify daemon for lbcd (https://github.com/lbryio/lbcd).
// Connects to lbcd's WebSocket RPC endpoint (`ws`), subscribes to block
// notifications and, for every connected block, invokes the `blocknotify`
// binary to notify the LBRY stratum server.
//
// lbcd already delivers the (LBRY 112-byte header) block hash in the
// blockconnected notification, so no manual header hashing is done here.
//
// Secrets are taken from flags or environment variables only:
//   LBCD_RPCUSER / LBCD_RPCPASS   lbcd RPC credentials (preferred over -user/-pass,
//                                 which are visible in the process list)
//   STRATUM_PASSWORD              inherited by the blocknotify child process

package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lbryio/lbcd/chaincfg/chainhash"
	"github.com/lbryio/lbcd/rpcclient"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		processName = flag.String("bin", "blocknotify", "Path to blocknotify executable")
		stratumDest = flag.String("stratum", "127.0.0.1:3334", "Stratum host:port")
		coinID      = flag.String("coinid", "1", "LBC database coin ID")
		lbcdHost    = flag.String("host", envOr("LBCD_RPCHOST", "127.0.0.1:9245"), "lbcd RPC host:port (env LBCD_RPCHOST)")
		lbcdUser    = flag.String("user", envOr("LBCD_RPCUSER", ""), "lbcd RPC username (env LBCD_RPCUSER)")
		lbcdPass    = flag.String("pass", envOr("LBCD_RPCPASS", ""), "lbcd RPC password (env LBCD_RPCPASS)")
		certFile    = flag.String("cert", envOr("LBCD_RPCCERT", "rpc.cert"), "Path to lbcd TLS rpc.cert (env LBCD_RPCCERT)")
		notls       = flag.Bool("notls", false, "Connect without TLS (lbcd --notls)")
		debug       = flag.Bool("debug", false, "Enable verbose logging")
	)
	flag.Parse()

	if *lbcdUser == "" || *lbcdPass == "" {
		log.Fatalln("lbcd RPC credentials missing: set LBCD_RPCUSER/LBCD_RPCPASS or -user/-pass")
	}

	ntfnHandlers := rpcclient.NotificationHandlers{
		OnBlockConnected: func(hash *chainhash.Hash, height int32, t time.Time) {
			if hash == nil {
				return
			}
			blockHash := hash.String()
			out, err := exec.Command(*processName, *stratumDest, *coinID, blockHash).CombinedOutput()
			if err != nil {
				log.Printf("blocknotify error for block %d %s: %v %s", height, blockHash, err, out)
			} else if *debug && len(out) > 0 {
				log.Printf("blocknotify output: %s", out)
			}
			if *debug {
				log.Printf("LBC block connected: height=%d hash=%s time=%s", height, blockHash, t)
			}
		},
	}

	var certs []byte
	if !*notls {
		var err error
		certs, err = os.ReadFile(filepath.Clean(*certFile))
		if err != nil {
			log.Fatalf("unable to read lbcd TLS cert: %v (use -notls if lbcd runs with --notls)", err)
		}
	}

	connCfg := &rpcclient.ConnConfig{
		Host:         *lbcdHost,
		Endpoint:     "ws",
		User:         *lbcdUser,
		Pass:         *lbcdPass,
		DisableTLS:   *notls,
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

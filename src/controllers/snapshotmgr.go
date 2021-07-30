/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

/*****************************************************************************/

import (
	"os"
	"os/signal"
	"syscall"
	"context"
	"net/http"
	"fmt"

	"github.com/go-logr/logr"
)

/*****************************************************************************/

type SnapshotMgr struct {
    server *http.Server
    log    logr.Logger
}

/*****************************************************************************/

/*
 * This function is the main function for the snapshot manager and is used
 * GET/PUT snapshots.
 */

func (mgr *SnapshotMgr) serve(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

/*****************************************************************************/

/*
 * This function is used to start the snapshot manager, and then wait until
 * we are told to terminate.
 */

func (mgr *SnapshotMgr) start() {
    // Define the http server and server handler
    mux := http.NewServeMux()

    mux.HandleFunc("/", mgr.serve)

    mgr.server.Handler = mux

    // Start listening for requests in a different thread.
    go func() {
        if err := mgr.server.ListenAndServe(); err != http.ErrServerClosed {
            mgr.log.Error(err, "Failed to start the snapshot manager")
        }
    }()

    // Wait and listen for the OS shutdown singal.
    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
        <-signalChan

    mgr.log.Info("Received a shutdown signal, shutting down the snapshot " +
                    "manager gracefully...")

    mgr.server.Shutdown(context.Background())
}

/*****************************************************************************/


/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

import (
    "github.com/go-logr/logr"
    "io/ioutil"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"
)

/*****************************************************************************/

/*
 * This function is used to determine the namespace in which the current
 * pod is running.
 */

func getLocalNamespace(log logr.Logger) (namespace string, err error) {
    var namespaceBytes []byte
    var clientCfg      *api.Config

    log.V(9).Info("Entering a function", "Function", "getLocalNamespace")

    /*
     * Work out the namespace which should be used.  In a Kubernetes
     * environment we read this from the namespace file, otherwise we use
     * the default namespace in the kubectl file.
     */

    namespace = "default"

    namespaceBytes, err = ioutil.ReadFile(k8sNamespaceFile)

    if err != nil {
        clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

        if err != nil {
            log.Error(err, "Failed to load the client configuration")
            return
        }

        namespace = clientCfg.Contexts[clientCfg.CurrentContext].Namespace
    } else {
        namespace = string(namespaceBytes)
    }

    log.V(5).Info("Found a namespace to use", "Namespace", namespace)

    return
}

/*****************************************************************************/


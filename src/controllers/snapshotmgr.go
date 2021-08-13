/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

/*****************************************************************************/

import (
    "bytes"
    "encoding/pem"
    "errors"
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "io/ioutil"
    "math/big"
    "net"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-logr/logr"

    "k8s.io/client-go/rest"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"

    apiV1  "k8s.io/api/core/v1"
    coreV1 "k8s.io/client-go/kubernetes/typed/core/v1"
    metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*****************************************************************************/

/*
 * Global variables.
 */

/*
 * The name of the kubernetes file which is used to determine the namespace
 * in which the snapshotmgr is running.
 */

var k8sNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

/*
 * The name of the secret which contains our credential information.
 */

var secretName = "verify-access-operator"

/*
 * The name of the various fields in the secret.
 */

var userFieldName  = "user"
var roPwdFieldName = "ro.pwd"
var rwPwdFieldName = "rw.pwd"
var certFieldName  = "tls.cert"
var keyFieldName   = "tls.key"

/*
 * The length of our passwords.
 */

var pwdLength = 36

/*
 * The length of the X509 key.
 */

var keyLength = 2048;

/*
 * The port on which we will listen for requests.
 */

var httpsPort = 7443

/*****************************************************************************/

type SnapshotMgr struct {
    config    *rest.Config
    log       logr.Logger

    server    *http.Server
    clientset *kubernetes.Clientset
    namespace string
    creds     map[string]string
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
 * This function is used to initialise the client which is used interact with
 * the kubernetes API.
 */

func (mgr *SnapshotMgr) initialiseClientset() (err error) {
    var namespaceBytes []byte
    var clientCfg      *api.Config

    /*
     * Work out the namespace which should be used.  In a Kubernetes
     * environment we read this from the namespace file, otherwise we use
     * the default namespace in the kubectl file.
     */

    mgr.namespace = ""

    namespaceBytes, err = ioutil.ReadFile(k8sNamespaceFile)

    if err != nil {
        clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

        if err != nil {
            mgr.log.Error(err, "Could not load the client configuration!")
            return
        }

        mgr.namespace = clientCfg.Contexts[clientCfg.CurrentContext].Namespace
    } else {
        mgr.namespace = string(namespaceBytes)
    }

    mgr.clientset, err = kubernetes.NewForConfig(mgr.config)
    if err != nil {
        mgr.log.Error(err, "Could not create a new client!")

        return
    }

    return
}

/*****************************************************************************/

/*
 * This function is used to generate a secure random password based on the 
 * specified password length.
 */

func (mgr *SnapshotMgr) generateRandomString(length int) (string, error) {
    const letters =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

    ret := make([]byte, length)

    for i := 0; i < length; i++ {
        num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))

        if err != nil {
            return "", err
        }

        ret[i] = letters[num.Int64()]
    }

    return string(ret), nil
}

/*****************************************************************************/

/*
 * The following function is used to generate a new public/private key
 * pair.
 */

func (mgr *SnapshotMgr) generateKey() (cert string, key string, err error) {

    /*
     * Generate the RSA key.
     */

    priv, err := rsa.GenerateKey(rand.Reader, keyLength)

    if err != nil {
        mgr.log.Error(err, "Could not generate an RSA key!")
        return
    }

    /*
     * Construct the x509 certificate.
     */

    host, _ := os.Hostname()

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            CommonName:   host,
            Organization: []string{"IBM"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 20),
        KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    if ip := net.ParseIP(host); ip != nil {
        template.IPAddresses = append(template.IPAddresses, ip)
    } else {
        template.DNSNames = append(template.DNSNames, host)
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
                &priv.PublicKey, priv)

    if err != nil {
        mgr.log.Error(err, "Could not generate the certificate!")
        return
    }

    /*
     * Convert the certificate.
     */

    out := &bytes.Buffer{}

    pem.Encode(out, &pem.Block{
                        Type:  "CERTIFICATE",
                        Bytes: derBytes,
                    })

    cert = out.String()

    /*
     * Convert the key.
     */

    out.Reset()

    pem.Encode(out, &pem.Block {
                Type:  "RSA PRIVATE KEY",
                Bytes: x509.MarshalPKCS1PrivateKey(priv),
            })

    key = out.String()

    return
}

/*****************************************************************************/

/*
 * This function is used to create our secret and populate the secret with
 * our required data.  This data includes:
 *     - the read-only credentials
 *     - the read-write credentials
 *     - the server certificate and key
 */

func (mgr *SnapshotMgr) createSecret(client coreV1.SecretInterface) (
                                        secret *apiV1.Secret, err error) {

    /*
     * Generate a random password for the read-only and read-write credentials.
     */

    ro_pwd, err := mgr.generateRandomString(pwdLength)

    if err != nil {
        mgr.log.Error(err, "Could not generate a password!")

        return
    }

    rw_pwd, err := mgr.generateRandomString(pwdLength)

    if err != nil {
        mgr.log.Error(err, "Could not generate a password!")

        return
    }

    /*
     * Generate a self signed certificate and key.
     */

    cert, key, err := mgr.generateKey()
    if err != nil {
        return
    }

    /*
     * Create the secret.
     */

    secret = &apiV1.Secret{
        Type: apiV1.SecretTypeOpaque,
        ObjectMeta: metaV1.ObjectMeta {
            Name: secretName,
        },
        StringData: map[string]string{
            userFieldName:  "apikey",
            rwPwdFieldName: rw_pwd,
            roPwdFieldName: ro_pwd,
            certFieldName:  cert,
            keyFieldName:   key,
        },
    }

    secret, err = client.Create(context.TODO(), secret, metaV1.CreateOptions{})

    if err != nil {
        mgr.log.Error(err, "Could not create the secret!")

        return
    }

    return
}

/*****************************************************************************/

/*
 * This function is used to load the relevant data from our secret.  We need
 * to obtain:
 *     - the read-only credentials
 *     - the read-write credentials
 *     - the server certificate and key
 */

func (mgr *SnapshotMgr) loadSecret() (err error) {
    var secretsClient coreV1.SecretInterface
    var secret        *apiV1.Secret

    /*
     * Attempt to retrieve the secret.
     */

    secretsClient = mgr.clientset.CoreV1().Secrets(mgr.namespace)
    secret, err   = secretsClient.Get(
                    context.TODO(), secretName, metaV1.GetOptions{})

    if err != nil {
        /*
         * The secret doesn't already exist and so we try to create the
         * secret now.
         */

        secret, err = mgr.createSecret(secretsClient)

        if err != nil {
            return
        }
    }

    /*
     * We now have the secret and so we need to store the data, also
     * checking that all of the required data exists.
     */

    mgr.creds = make(map[string]string)

    keys := []string {
                    userFieldName,
                    roPwdFieldName,
                    rwPwdFieldName,
                    certFieldName,
                    keyFieldName,
        }

    for _, key := range keys {
        value, ok := secret.Data[key]

        if !ok {
            mgr.log.Error(err, fmt.Sprintf(
                    "The secret, %s, is missing a required field: '%s'!",
                    secretName, key))

            err = errors.New("Missing field")

            return
        }

        mgr.creds[key] = string(value)
    }

    return
}

/*****************************************************************************/

/*
 * This function is used to start the snapshot manager, and then wait until
 * we are told to terminate.
 */

func (mgr *SnapshotMgr) start() {
    var err error

    mgr.log.Info(
        fmt.Sprintf("Starting the snapshot manager on port: %v", httpsPort))

    /*
     * Initialise this object.
     */

    err = mgr.initialiseClientset()
    if err != nil {
        return
    }

    err = mgr.loadSecret()
    if err != nil {
        return
    }

    /*
     * Define the http server and server handler.
     */

    pair, err := tls.X509KeyPair(
                        []byte(mgr.creds[certFieldName]),
                        []byte(mgr.creds[keyFieldName]))

    if err != nil {
        mgr.log.Error(err, "Failed to generate the X509 key pair")

        return
    }

    mgr.server = &http.Server{
        Addr:      fmt.Sprintf(":%v", httpsPort),
        TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},

    }

    mux := http.NewServeMux()

    mux.HandleFunc("/", mgr.serve)

    mgr.server.Handler = mux

    /*
     * Start listening for requests in a different thread.
     */

    go func() {
        if err := mgr.server.ListenAndServeTLS("", "");
                        err != http.ErrServerClosed {
            mgr.log.Error(err, "Failed to start the snapshot manager")
        }
    }()

    /*
     * Wait and listen for the OS shutdown singal.
     */

    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
        <-signalChan

    mgr.log.Info("Received a shutdown signal, shutting down the snapshot " +
                    "manager gracefully...")

    mgr.server.Shutdown(context.Background())
}

/*****************************************************************************/


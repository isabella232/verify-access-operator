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
    "io"
    "io/ioutil"
    "math/big"
    "net"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/go-logr/logr"

    "k8s.io/apimachinery/pkg/types"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"

    apiV1   "k8s.io/api/core/v1"
    appsV1  "k8s.io/client-go/kubernetes/typed/apps/v1"
    coreV1  "k8s.io/client-go/kubernetes/typed/core/v1"
    metaV1  "k8s.io/apimachinery/pkg/apis/meta/v1"
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

var operatorName = "verify-access-operator"

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

/*
 * The directory on the file system which holds our uploaded files.
 */

var dataRoot = "/data"

/*
 * The maximum amount of memory which should be used when receiving a 
 * file.
 */

var maxMemory = int64(1024)

/*****************************************************************************/

type SnapshotMgr struct {
    config    *rest.Config
    log       logr.Logger
    appName   string

    server    *http.Server
    creds     map[string]string

    mutex     *sync.Mutex
}

/*****************************************************************************/

/*
 * This function is used to trigger a rolling restart of our deployments.  This
 * will occur whenever a new snapshot is uploaded.
 */

func (mgr *SnapshotMgr) rollingRestart() {
    /*
     * Grab a lock to ensure that we don't process multiple simultaneous
     * restarts.
     */

    mgr.mutex.Lock()

    /*
     * Create a new client based on our configuration.
     */

    appsV1Client, err := appsV1.NewForConfig(mgr.config)
    if err != nil {
        mgr.log.Error(err, "Failed to create a new K8S Application client")

        mgr.mutex.Unlock()

        return
    }

    /*
     * Retrieve the existing deployments for our operator.
     */

    deployments, err := appsV1Client.Deployments("").List(
                    context.TODO(),
                    metaV1.ListOptions{
                        LabelSelector: fmt.Sprintf("app=%s", mgr.appName),
                    })
    if err != nil {
        mgr.log.Error(err, "Failed to list deployments")

        mgr.mutex.Unlock()

        return
    }

    /*
     * Now we need to iterate over each of the deployments, performing
     * a rolling restart of the deployment.
     */

    for _, deployment := range deployments.Items {

        /*
         * Determine the revision number of the deployment.  This is incremented
         * to trigger a rolling update.
         */

        revision, err := strconv.Atoi(
                            deployment.Spec.Template.Annotations["revision"])

        if err != nil {
            revision = 1
        } else {
            revision++
        }

        /*
         * Patch the deployment descriptor with the incremented revision
         * number.
         */

	payloadBytes := fmt.Sprintf(
                    "{\"spec\":" +
                      "{\"template\":" +
                        "{\"metadata\":" +
                          "{\"annotations\":{" +
                            "\"revision\":\"%d\"}" +
                          "}" +
                        "}" +
                      "}" +
                    "}", revision)

        _, err = appsV1Client.Deployments(deployment.Namespace).Patch(
                        context.TODO(),
                        deployment.Name,
                        types.StrategicMergePatchType,
                        []byte(payloadBytes),
                        metaV1.PatchOptions{})

        if err != nil {
            mgr.log.Error(err, fmt.Sprintf(
                    "Failed to update the deployment: %s", deployment.Name))

            mgr.mutex.Unlock()

            return
        }
    }

    mgr.mutex.Unlock()
}

/*****************************************************************************/

/*
 * This function is the main function for the snapshot manager and is used
 * GET/PUT snapshots.
 */

func (mgr *SnapshotMgr) serve(w http.ResponseWriter, r *http.Request) {
    /*
     * Check the authorization to this Web server.  The username should always
     * be the same, but we use a different password for the GET/POST methods.
     */

    username, password, _ := r.BasicAuth()

    authOk := mgr.creds[userFieldName] == username &&
                (mgr.creds[rwPwdFieldName] == password ||
                  (r.Method == "GET" && mgr.creds[roPwdFieldName] == password))

    if !authOk {
        w.Header().Set("WWW-Authenticate",
                        fmt.Sprintf("Basic realm=\"%s\"", operatorName))

        http.Error(w,
            http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

        return
    }

    /*
     * Validate the supplied path, and from this determine the name of the
     * file which will be used.  We need to ensure that we don't traverse
     * out of our data path.  The only valid directories are: '/fixpacks',
     * and '/snapshots'.
     */

    isValid := false

    if (strings.HasPrefix(r.URL.Path, "/fixpacks/")) {
        basePath := filepath.Base(filepath.Clean(r.URL.Path))

        if r.URL.Path == "/fixpacks/" + basePath {
            isValid = true
        }
    } else if (strings.HasPrefix(r.URL.Path, "/snapshots/")) {
        basePath := filepath.Base(filepath.Clean(r.URL.Path))

        if r.URL.Path == "/snapshots/" + basePath &&
                strings.HasPrefix(basePath, "isva_") &&
                strings.HasSuffix(basePath, ".snapshot") {
            isValid = true
        }
    }

    if !isValid {
        http.Error(w,
            http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

        return
    }

    fileName := filepath.Join(dataRoot, r.URL.Path)

    /*
     * Process the request based on the specified method.
     */

    switch r.Method {
        /*
         * For a GET we simply want to return the file.  The ServeFile function
         * will take care of constructing the response.
         */

        case "GET":
            http.ServeFile(w, r, fileName)

        /*
         * For a POST we want to save the supplied file.
         */

        case "POST":
            /*
             * Retrieve the file parameter from the form.
             */

            r.ParseMultipartForm(maxMemory)

            file, _, err := r.FormFile("file")

            if err != nil {
                http.Error(w,
                    http.StatusText(http.StatusBadRequest),
                    http.StatusBadRequest)

                return
            }

            defer file.Close()

            /*
             * Create the file which is to be uploaded.
             */

            dst, err := os.Create(fileName)

            if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
            }

            defer dst.Close()

            /*
             * Save the file.
             */

            _, err = io.Copy(dst, file)

            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            /*
             * Request a restart of all running containers in a separate
             * thread.
             */

            go mgr.rollingRestart()

            /*
             *  Return a '201 Created' response.
             */

            http.Error(w, "", http.StatusCreated)

        /*
         * For a DELETE we want to attempt to delete the specified file.  The
         * response will be different based on whether the file exists, and we
         * were able to successfully delete the file.
         */

        case "DELETE":
            err := os.Remove(fileName)

            var rspCode int
            var rspText string

            if err == nil {
                rspCode = http.StatusNoContent
                rspText = ""
            } else if os.IsNotExist(err) {
                rspCode = http.StatusNotFound
                rspText = http.StatusText(http.StatusNotFound)
            } else {
                rspCode = http.StatusInternalServerError
                rspText = err.Error()
            }

            http.Error(w, rspText, rspCode)

        /*
         * All other methods are not supported.
         */

	default:
            http.Error(w,
                http.StatusText(http.StatusNotImplemented),
                http.StatusNotImplemented)
    }
}

/*****************************************************************************/

/*
 * This function is used to determine the namespace in which the current
 * pod is running.
 */

func (mgr *SnapshotMgr) getNamespace() (namespace string, err error) {
    var namespaceBytes []byte
    var clientCfg      *api.Config

    /*
     * Work out the namespace which should be used.  In a Kubernetes
     * environment we read this from the namespace file, otherwise we use
     * the default namespace in the kubectl file.
     */

    namespace = ""

    namespaceBytes, err = ioutil.ReadFile(k8sNamespaceFile)

    if err != nil {
        clientCfg, err = clientcmd.NewDefaultClientConfigLoadingRules().Load()

        if err != nil {
            mgr.log.Error(err, "Could not load the client configuration!")
            return
        }

        namespace = clientCfg.Contexts[clientCfg.CurrentContext].Namespace
    } else {
        namespace = string(namespaceBytes)
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
            Name: operatorName,
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
    var namespace     string

    /*
     * Work out the namespace in which we are running.
     */

    namespace, err = mgr.getNamespace()

    if err != nil {
        return
    }

    /*
     * Create a new client based on our current configuration.
     */

    clientset, err := kubernetes.NewForConfig(mgr.config)
    if err != nil {
        mgr.log.Error(err, "Could not create a new client!")

        return
    }

    /*
     * Attempt to retrieve the secret.
     */

    secretsClient = clientset.CoreV1().Secrets(namespace)
    secret, err   = secretsClient.Get(
                        context.TODO(), operatorName, metaV1.GetOptions{})

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
                    operatorName, key))

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

    err = mgr.loadSecret()
    if err != nil {
        return
    }

    mgr.mutex = &sync.Mutex{}

    /*
     * Create the directories which will store our data.
     */

    dirs := []string {
                    dataRoot,
                    filepath.Join(dataRoot, "snapshots"),
                    filepath.Join(dataRoot, "fixpacks"),
        }

    for _, dir := range dirs {
        err = os.Mkdir(dir, 0700)

        if err != nil && !os.IsExist(err) {
            mgr.log.Error(err,
                    fmt.Sprintf("Failed to create the data directory: %s", dir))
            return
        }
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


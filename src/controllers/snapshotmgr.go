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

    "sigs.k8s.io/controller-runtime/pkg/client"

    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/types"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/kubernetes"

    apiV1   "k8s.io/api/core/v1"
    appsV1  "k8s.io/client-go/kubernetes/typed/apps/v1"
    coreV1  "k8s.io/client-go/kubernetes/typed/core/v1"
    metaV1  "k8s.io/apimachinery/pkg/apis/meta/v1"

    ibmv1 "github.com/ibm-security/verify-access-operator/api/v1"
)

/*****************************************************************************/

type SnapshotMgr struct {
    config       *rest.Config
    scheme       *runtime.Scheme

    log          logr.Logger

    server       *http.Server
    creds        map[string]string

    restartMutex *sync.Mutex
    webMutex     *sync.RWMutex
}

/*****************************************************************************/

/*
 * This function is used to trigger a rolling restart of our deployments.  This
 * will occur whenever a new snapshot is uploaded.
 */

func (mgr *SnapshotMgr) rollingRestart(path string, modified string) {

    mgr.log.V(9).Info("Entering a function", "Function", "rollingRestart")

    /*
     * Work out the list of modified services.
     */

    var services []string

    if len(modified) > 0 {
        services = strings.Split(strings.Replace(modified, ":", "-", -1), ",")
    }

    /*
     * Grab a lock to ensure that we don't process multiple simultaneous
     * restarts.
     */

    mgr.restartMutex.Lock()

    /*
     * Work out the snapshot identifier, if a snapshot has been provided.
     */

    snapshotId := ""

    if (strings.HasPrefix(path, "/snapshots/")) {
        snapshotName := filepath.Base(filepath.Clean(path))

        /*
         * We now need to pull out the snapshot identifier from the
         * name of the snapshot.  The snapshot name is of the format: 
         *    isva_<version>_<snapshotid>.snapshot
         */

        parts := strings.Split(snapshotName, "_")

        if len(parts) != 3 {
            mgr.restartMutex.Unlock()

            mgr.log.Info("No deployments will be restarted as the " +
                    "snapshot name is invalid", "Snapshot.Name", snapshotName);

            return;
        }

        parts = strings.Split(parts[2], ".")

        if len(parts) != 2 {
            mgr.restartMutex.Unlock()

            mgr.log.Info("No deployments will be restarted as the " +
                    "snapshot name is invalid", "Snapshot.Name", snapshotName);

            return;
        }

        snapshotId = parts[0]

        mgr.log.V(5).Info("Processing a snapshot", "Snapshot.Id", "snapshotId")
    }

    /*
     * Create a new client based on our configuration.
     */

    appsV1Client, err := appsV1.NewForConfig(mgr.config)
    if err != nil {
        mgr.restartMutex.Unlock()

        mgr.log.Error(err, "Failed to create a new K8S Application client")

        return
    }

    rtClient, err := client.New(mgr.config,
                                client.Options{
                                    Scheme: mgr.scheme,
                                })

    if err != nil {
        mgr.restartMutex.Unlock()

        mgr.log.Error(err, "Failed to create a new controller runtime client")

        return
    }

    /*
     * Restart the deployments.
     */

    if len(services) > 0 {
        for _, service := range services {
            mgr.restartDeployments(
                        path,
                        snapshotId,
                        fmt.Sprintf("kind=%s, service=%s", kindName, service),
                        appsV1Client,
                        rtClient)
        }
    } else {
        mgr.restartDeployments(
                        path,
                        snapshotId,
                        fmt.Sprintf("kind=%s", kindName),
                        appsV1Client,
                        rtClient)
    }

    /*
     * Finished, so we can release our lock.
     */

    mgr.restartMutex.Unlock()
}

/*****************************************************************************/

/*
 * This function is used to trigger a rolling restart of the specified 
 * deployments.  
 */

func (mgr *SnapshotMgr) restartDeployments(
                                path         string,
                                snapshotId   string,
                                labels       string,
                                appsV1Client *appsV1.AppsV1Client,
                                rtClient     client.Client) {

    /*
     * Retrieve the existing deployments for our operator.
     */

    deployments, err := appsV1Client.Deployments("").List(
                    context.TODO(),
                    metaV1.ListOptions{
                        LabelSelector: labels,
                    })

    if err != nil {
        mgr.log.Error(err, "Failed to list deployments")

        return
    }

    /*
     * Now we need to iterate over each of the deployments, performing
     * a rolling restart of the deployment.
     */

    for _, deployment := range deployments.Items {

        mgr.log.V(5).Info("Checking a deployment",
                                "Deployment.Namespace", deployment.Namespace,
                                "Deployment.Name", deployment.Name)

        /*
         * Detect and retrieve the custom resource for this deployment.  The 
         * name of the custom resource is contained in the VerifyAccess_cr 
         * label.
         */

        crName := deployment.Labels["VerifyAccess_cr"]

        if len(crName) == 0 {
            mgr.log.Info("The deployment does not have a VerifyAccess_cr label",
                                "Deployment.Namespace", deployment.Namespace,
                                "Deployment.Name", deployment.Name)

            continue
        }

        verifyaccess := &ibmv1.IBMSecurityVerifyAccess{}

        err = rtClient.Get(context.TODO(),
                            client.ObjectKey{
                                Namespace: deployment.Namespace,
                                Name:      crName,
                            },
                            verifyaccess)

        if err != nil {
            mgr.log.Error(err,
                "Failed to retrieve the IBMSecurityVerifyAccess resource",
                "CustomResource.Name", crName)

            continue
        }

        /*
         * We don't bother to restart the deployment if the AutoRestart field
         * has been set to false.
         */

        if !verifyaccess.Spec.AutoRestart {
            mgr.log.Info("Not performing an autorestart of the deployment as " +
                    "the AutoRestart field is set to false",
                        "Deployment.Namespace", deployment.Namespace,
                        "Deployment.Name", deployment.Name)

            continue
        }

        /*
         * Check to see if the supplied file is actually used by the
         * deployment.
         */

        if (strings.HasPrefix(path, "/fixpacks/")) {
            /*
             * A new fixpack has been supplied and so we only worry about
             * restarting the deployment if it is currently using this
             * fixpack.
             */

            fixpackName := filepath.Base(filepath.Clean(path))

            fixpackInUse := false

            for _, fixpack := range verifyaccess.Spec.Fixpacks {
                if fixpackName == fixpack {
                    fixpackInUse = true
                    break
                }
            }

            if ! fixpackInUse {
                mgr.log.Info("Not performing an autorestart as the " +
                        "supplied fixpack is not used by the deployment",
                        "Deployment.Namespace", deployment.Namespace,
                        "Deployment.Name", deployment.Name,
                        "Fixpack.Name", fixpackName)

                continue
            }

        } else if (strings.HasPrefix(path, "/snapshots/")) {
            /*
             * A new snapshot has been uploaded.  We need to see if the
             * snapshot identifier for the deployment matches our supplied
             * snapshot identifier.
             */

            if snapshotId != verifyaccess.Spec.SnapshotId {
                mgr.log.Info("Not performing an autorestart as the " +
                        "supplied snapshot is not used by the deployment",
                        "Deployment.Namespace", deployment.Namespace,
                        "Deployment.Name", deployment.Name,
                        "Deployment.Snapshot.Id", verifyaccess.Spec.SnapshotId,
                        "Snapshot.Id", snapshotId)

                continue
            }
        }

        /*
         * Determine the revision number of the deployment.  This is incremented
         * to trigger a rolling update.
         */

        mgr.log.Info("Performing a rolling restart of the deployment",
                                "Deployment.Namespace", deployment.Namespace,
                                "Deployment.Name", deployment.Name)

        revision, err := strconv.Atoi(
                            deployment.Spec.Template.Annotations["revision"])

        if err != nil {
            revision = 1
        } else {
            revision++
        }

        mgr.log.V(5).Info("New revision number", "Revision", revision)

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
            mgr.log.Error(err, "Failed to update the deployment",
                            "Deployment.Name", deployment.Name)

            return
        }

        mgr.log.V(5).Info("Successfully updated the deployment")
    }
}

/*****************************************************************************/

/*
 * This function is the main function for the snapshot manager and is used
 * GET/PUT snapshots.
 */

func (mgr *SnapshotMgr) serve(w http.ResponseWriter, r *http.Request) {

    mgr.log.V(9).Info("Entering a function", "Function", "serve")

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

        mgr.log.V(5).Info("Authentication failed", "Username", username)

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

        mgr.log.V(5).Info("An invalid path has been requested",
                            "Path", r.URL.Path)

        return
    }

    fileName := filepath.Join(dataRoot, r.URL.Path)

    /*
     * Work out the client of the request.
     */


    client := r.URL.Query().Get("client")

    if len(client) == 0 {
        client = r.Header.Get("X-Forwarded-For")

        if len(client) == 0 {
            client = r.RemoteAddr

            if len(client) == 0 {
                client = "unknown"
            }
        }
    }

    /*
     * Process the request based on the specified method.
     */

    switch r.Method {
        /*
         * For a GET we simply want to return the file.  The ServeFile function
         * will take care of constructing the response.
         */

        case "GET":
            mgr.log.Info("Processing a GET", "Path", r.URL.Path, "Client", client)

            mgr.webMutex.RLock()
            http.ServeFile(w, r, fileName)
            mgr.webMutex.RUnlock()

        /*
         * For a POST we want to save the supplied file.
         */

        case "POST":
            /*
             * Work out some of the information associated with the request and
             * then log the request.
             */

            modified    := r.URL.Query().Get("modified")
            modifiedStr := modified

            if len(modified) == 0 {
                modifiedStr = "all"
            }

            mgr.log.Info("Processing a POST",
                            "Path",     r.URL.Path,
                            "Modified", modifiedStr,
                            "Client",   client)

            /*
             * Retrieve the file parameter from the form.
             */

            r.ParseMultipartForm(maxMemory)

            file, _, err := r.FormFile("file")

            if err != nil {
                http.Error(w,
                    http.StatusText(http.StatusBadRequest),
                    http.StatusBadRequest)

                mgr.log.V(5).Error(err, "An invalid POST has been received")

                return
            }

            defer file.Close()

            /*
             * Create the file which is to be uploaded.
             */

            mgr.webMutex.Lock()

            dst, err := os.Create(fileName)

            if err != nil {
                mgr.webMutex.Unlock()

		http.Error(w, err.Error(), http.StatusInternalServerError)

                mgr.log.V(5).Error(err, "Failed to create the file",
                                        "File", fileName)

		return
            }

            defer dst.Close()

            /*
             * Save the file.
             */

            _, err = io.Copy(dst, file)

            if err != nil {
                mgr.webMutex.Unlock()

                http.Error(w, err.Error(), http.StatusInternalServerError)

                mgr.log.V(5).Error(err, "Failed to copy the file",
                                        "File", fileName)

                return
            }

            mgr.webMutex.Unlock()

            /*
             * Request a restart of all running containers in a separate
             * thread.
             */

            go mgr.rollingRestart(filepath.Clean(r.URL.Path), modified)

            /*
             *  Return a '201 Created' response.
             */

            http.Error(w, "", http.StatusCreated)

            mgr.log.V(5).Info("The file has been saved", "File", fileName)

        /*
         * For a DELETE we want to attempt to delete the specified file.  The
         * response will be different based on whether the file exists, and we
         * were able to successfully delete the file.
         */

        case "DELETE":
            mgr.log.Info("Processing a DELETE",
                            "Path", r.URL.Path, "Client", client)

            mgr.webMutex.Lock()
            err := os.Remove(fileName)
            mgr.webMutex.Unlock()

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

            if err == nil {
                mgr.log.V(5).Error(err, "Failed to delete the file",
                                        "File", fileName)
            } else {
                mgr.log.V(5).Info("Successfully deleted the file",
                                        "File", fileName)
            }

            http.Error(w, rspText, rspCode)

        /*
         * All other methods are not supported.
         */

	default:
            mgr.log.V(5).Info("Received a request with an invalid method",
                                "Path",   r.URL.Path,
                                "Client", client,
                                "Method", r.Method)

            http.Error(w,
                http.StatusText(http.StatusNotImplemented),
                http.StatusNotImplemented)

    }
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

    mgr.log.V(9).Info("Entering a function", "Function", "generateKey")

    /*
     * Generate the RSA key.
     */

    priv, err := rsa.GenerateKey(rand.Reader, keyLength)

    if err != nil {
        mgr.log.Error(err, "Failed to generate an RSA key")
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
        mgr.log.Error(err, "Failed to generate the certificate")
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

func (mgr *SnapshotMgr) createSecret(
                client coreV1.SecretInterface, namespace string) (
                                        secret *apiV1.Secret, err error) {

    mgr.log.V(9).Info("Entering a function", "Function", "createSecret")

    /*
     * Generate a random password for the read-only and read-write credentials.
     */

    ro_pwd, err := mgr.generateRandomString(pwdLength)

    if err != nil {
        mgr.log.Error(err, "Failed to generate a password")

        return
    }

    rw_pwd, err := mgr.generateRandomString(pwdLength)

    if err != nil {
        mgr.log.Error(err, "Failed to generate a password")

        return
    }

    /*
     * Generate a self signed certificate and key.
     */

    cert, key, err := mgr.generateKey()
    if err != nil {
        return
    }

    url := fmt.Sprintf("https://%s.%s.svc.cluster.local:%d",
                                    serviceName, namespace, httpsPort)

    /*
     * Create the secret.
     */

    secret = &apiV1.Secret{
        Type: apiV1.SecretTypeOpaque,
        ObjectMeta: metaV1.ObjectMeta {
            Name: operatorName,
        },
        StringData: map[string]string{
            userFieldName:  snapshotMgrUser,
            urlFieldName:   url,
            rwPwdFieldName: rw_pwd,
            roPwdFieldName: ro_pwd,
            certFieldName:  cert,
            keyFieldName:   key,
        },
    }

    secret, err = client.Create(context.TODO(), secret, metaV1.CreateOptions{})

    if err != nil {
        mgr.log.Error(err, "Failed to create the secret",
                            "Secret.Name", operatorName)

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

    mgr.log.V(9).Info("Entering a function", "Function", "loadSecret")

    /*
     * Work out the namespace in which we are running.
     */

    namespace, err = getLocalNamespace(mgr.log)

    if err != nil {
        return
    }

    /*
     * Create a new client based on our current configuration.
     */

    clientset, err := kubernetes.NewForConfig(mgr.config)
    if err != nil {
        mgr.log.Error(err, "Failed to create a new client")

        return
    }

    /*
     * Attempt to retrieve the secret.
     */

    secretsClient = clientset.CoreV1().Secrets(namespace)
    secret, err   = secretsClient.Get(
                        context.TODO(), operatorName, metaV1.GetOptions{})

    if err != nil {
        mgr.log.V(5).Info("Creating the secret", "Secret.Name", operatorName)

        /*
         * The secret doesn't already exist and so we try to create the
         * secret now.
         */

        secret, err = mgr.createSecret(secretsClient, namespace)

        if err != nil {
            return
        }
    } else {
        mgr.log.V(5).Info("Found the secret", "Secret.Name", operatorName)
    }

    /*
     * We now have the secret and so we need to store the data, also
     * checking that all of the required data exists.
     */

    mgr.creds = make(map[string]string)

    keys := []string {
                    userFieldName,
                    urlFieldName,
                    roPwdFieldName,
                    rwPwdFieldName,
                    certFieldName,
                    keyFieldName,
        }

    for _, key := range keys {
        value, ok := secret.Data[key]

        if !ok {
            mgr.log.Error(err, "The secret is missing a required field",
                    "Secret.Name", operatorName, "Field.Name", key)

            err = errors.New("Missing field")

            return
        }

        mgr.creds[key] = string(value)
    }

    return
}

/*****************************************************************************/

/*
 * This function is used to initialize the snapshot manager.
 */

func (mgr *SnapshotMgr) initialize() (err error) {
    /*
     * Initialise this object.
     */

    err = mgr.loadSecret()
    if err != nil {
        return
    }

    mgr.restartMutex = &sync.Mutex{}
    mgr.webMutex     = &sync.RWMutex{}

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
            mgr.log.Error(err, "Failed to create the data directory",
                                "Directory", dir)

            return
        } else {
            err = nil
        }

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

    mgr.log.Info("Starting the snapshot manager", "Port", httpsPort)

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

    mgr.log.V(5).Info("Waiting for Web requests")

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
                    "manager gracefully")

    mgr.server.Shutdown(context.Background())
}

/*****************************************************************************/


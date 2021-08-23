/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

/*****************************************************************************/

/*
 * The name of the kubernetes file which is used to determine the namespace
 * in which the snapshotmgr is running.
 */

const k8sNamespaceFile string =
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

/*
 * The name which is given to our operator.  This same name will also be
 * used as the name of the secret which is generated for the operator.
 */

const operatorName string = "verify-access-operator"

/*
 * The name of our exported snapshot manager configuration service.
 */

const serviceName string =
            "verify-access-operator-controller-manager-snapshot-service"

/*
 * The custom resource type.
 */

const kindName string = "IBMSecurityVerifyAccess"

/*
 * The name of the user which is used to authenticate to the snapshot
 * manager.
 */

const snapshotMgrUser string = "apikey"

/*
 * The name of the various fields in the secret.
 */

const userFieldName  string = "user"
const roPwdFieldName string = "ro.pwd"
const rwPwdFieldName string = "rw.pwd"
const certFieldName  string = "tls.cert"
const keyFieldName   string = "tls.key"

/*
 * The length of our generated passwords.
 */

const pwdLength int = 36

/*
 * The length of the generated X509 key.
 */

const keyLength int = 2048;

/*
 * The port on which the snapshot manager will listen for requests.
 */

const httpsPort int = 7443

/*
 * The directory on the file system which holds our uploaded files.
 */

const dataRoot string = "/data"

/*
 * The maximum amount of memory which should be used when receiving a 
 * file.
 */

const maxMemory int64 = 1024



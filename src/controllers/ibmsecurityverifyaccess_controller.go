/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

/*****************************************************************************/

import (
    apiv1  "k8s.io/api/core/v1"
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    "k8s.io/apimachinery/pkg/api/errors"
    "k8s.io/apimachinery/pkg/types"

    "context"
    "strings"
    "sync"
    "time"

    "github.com/go-logr/logr"

    "k8s.io/apimachinery/pkg/runtime"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"

    ibmv1 "github.com/ibm-security/verify-access-operator/api/v1"
)

/*****************************************************************************/

/*
 * The IBMSecurityVerifyAccessReconciler structure reconciles an 
 * IBMSecurityVerifyAccess object.
 */

type IBMSecurityVerifyAccessReconciler struct {
    client.Client

    Log            logr.Logger
    Scheme         *runtime.Scheme
    localNamespace string
    snapshotMgr    SnapshotMgr
    secretMutex    *sync.Mutex
}

/*****************************************************************************/

//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifyaccesses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifyaccesses/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ibm.com,resources=ibmsecurityverifyaccesses/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

/*****************************************************************************/

/*
 * Reconcile is part of the main kubernetes reconciliation loop which aims to
 * move the current state of the cluster closer to the desired state.
 *
 * For more details, check Reconcile and its Result here:
 * - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
 */

func (r *IBMSecurityVerifyAccessReconciler) Reconcile(
            ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

    r.Log.V(9).Info("Entering a function", "Function", "Reconcile")

    /*
     * Fetch the definition document.
     */

    verifyaccess := &ibmv1.IBMSecurityVerifyAccess{}
    err          := r.Get(ctx, req.NamespacedName, verifyaccess)

    if err != nil {
        if errors.IsNotFound(err) {
            /*
             * The requested object was not found.  It could have been deleted 
             * after the reconcile request.  
             */

            r.Log.Info("The VerifyAccess resource was not found. " +
                "Ignoring this error since the object must have been deleted")

            err = nil
        } else {
            /*
             * There was an error reading the object - requeue the request.
             */

            r.Log.Error(err, "Failed to get the VerifyAccess resource")
        }

        return ctrl.Result{}, err
    }

    /*
     * Check if the deployment already exists, and if one doesn't we create a 
     * new one now.
     */

    found := &appsv1.Deployment{}
    err    = r.Get(
                    ctx,
                    types.NamespacedName{
                        Name:      verifyaccess.Name,
                        Namespace: verifyaccess.Namespace},
                    found)

    if err != nil {
        if errors.IsNotFound(err) {
            /*
             * The deployment requires a secret which contains the snapshot
             * manager credentials.  We need to create the secret in the
             * destination namespace if it doesn't already exist.
             */

            err = r.createSecret(ctx, verifyaccess)

            if err == nil {
                /*
                 * A deployment does not already exist and so we create a new 
                 * deployment.
                 */

                dep := r.deploymentForVerifyAccess(verifyaccess)

                r.Log.Info("Creating a new deployment", "Deployment.Namespace",
                                dep.Namespace, "Deployment.Name", dep.Name)

                err = r.Create(ctx, dep)

                if err != nil {
                    r.Log.Error(err, "Failed to create the new deployment",
                                "Deployment.Namespace", dep.Namespace,
                                "Deployment.Name", dep.Name)
                }
            }

        } else {
            r.Log.Error(err, "Failed to retrieve the Deployment resource")
        }

        r.setCondition(err, true, ctx, verifyaccess)

        return ctrl.Result{}, err

    }

    /*
     * The deployment already exists.  We now need to check to see if any
     * of our CR fields have been updated which will require an update of
     * the deployment.
     */

    r.Log.V(5).Info("Found a matching deployment",
                                "Deployment.Namespace", found.Namespace,
                                "Deployment.Name", found.Name)

    replicas := verifyaccess.Spec.Replicas

    if *found.Spec.Replicas != replicas {
        found.Spec.Replicas = &replicas

        err = r.Update(ctx, found)

        if err != nil {
            r.Log.Error(err, "Failed to update deployment",
                                "Deployment.Namespace", found.Namespace,
                                "Deployment.Name", found.Name)
        } else {
            r.Log.Info("Updated an existing deployment",
                                "Deployment.Namespace", found.Namespace,
                                "Deployment.Name", found.Name)
        }

        r.setCondition(err, false, ctx, verifyaccess)

        return ctrl.Result{}, err
    }

    return ctrl.Result{}, nil
}

/*****************************************************************************/

/*
 * The following function is used to wrap the logic which updates the
 * condition for a failure.
 */

func (r *IBMSecurityVerifyAccessReconciler) setCondition(
                err      error,
                isCreate bool,
                ctx      context.Context,
                m        *ibmv1.IBMSecurityVerifyAccess) error {

    var condReason  string
    var condMessage string

    if isCreate {
        condReason  = "DeploymentCreated"
        condMessage = "The deployment has been created."
    } else {
        condReason  = "DeploymentUpdated"
        condMessage = "The deployment has been updated."
    }

    currentTime := metav1.NewTime(time.Now())

    if err == nil {
        m.Status.Conditions = []metav1.Condition{{
            Type:               "Available",
            Status:             metav1.ConditionTrue,
            Reason:             condReason,
            Message:            condMessage,
            LastTransitionTime: currentTime,
        }}
    } else {
        m.Status.Conditions = []metav1.Condition{{
            Type:               "Available",
            Status:             metav1.ConditionFalse,
            Reason:             condReason,
            Message:            err.Error(),
            LastTransitionTime: currentTime,
        }}
    }

    if err := r.Status().Update(ctx, m); err != nil {
        r.Log.Error(err, "Failed to update the condition for the resource",
                                "Deployment.Namespace", m.Namespace,
                                "Deployment.Name", m.Name)

        return err
    }

    return nil
}

/*****************************************************************************/

/*
 * The following function is used to create the secret which is used by
 * the deployment.
 */

func (r *IBMSecurityVerifyAccessReconciler) createSecret(
                    ctx context.Context,
                    m   *ibmv1.IBMSecurityVerifyAccess) (err error) {

    r.secretMutex.Lock()

    /*
     * Check to see if the secret already exists.
     */

    secret := &corev1.Secret{}
    err     = r.Get(
                    ctx,
                    types.NamespacedName{
                        Name:      operatorName,
                        Namespace: m.Namespace,
                    },
                    secret)

    if err != nil {
        if errors.IsNotFound(err) {
            /*
             * The secret doesn't already exist and so we need to create
             * the secret now.
             */

            r.Log.V(5).Info("Creating the secret",
                                "Deployment.Namespace", m.Namespace,
                                "Secret.Name", operatorName)

            secret = &corev1.Secret{
                    Type: apiv1.SecretTypeOpaque,
                    ObjectMeta: metav1.ObjectMeta {
                        Name:      operatorName,
                        Namespace: m.Namespace,
                    },
                    StringData: map[string]string {
                        userFieldName:  snapshotMgrUser,
                        urlFieldName:   r.snapshotMgr.creds[urlFieldName],
                        roPwdFieldName: r.snapshotMgr.creds[roPwdFieldName],
                    },
                }

            err = r.Create(ctx, secret)

            if err != nil {
                r.Log.Error(err, "Failed to create the secret",
                            "Deployment.Namespace", m.Namespace,
                            "Secret.Name", operatorName)
            }
        } else {
            r.Log.Error(err, "Failed to retrieve the secret",
                            "Deployment.Namespace", m.Namespace,
                            "Secret.Name", operatorName)
        }
    } else {
        r.Log.V(5).Info("Found an existing secret",
                                "Deployment.Namespace", m.Namespace,
                                "Secret.Name", operatorName)
    }

    r.secretMutex.Unlock()

    return
}

/*****************************************************************************/

/*
 * The following function is used to return a VerifyAccess Deployment object.
 *
 * We map the following IBMSecurityVerifyAccess attributes to a corresponding
 * attribute in the Deployment structure:
 *
 *    IBMSecurityVerifyAccess spec | Deployment spec
 *    ---------------------------- | ---------------
 *    replicas                     | replicas
 *    image                        | template.spec.containers[0].image
 *    snapshotId                   | template.spec.containers[0].env
 *    fixpacks                     | template.spec.containers[0].env
 *    instance                     | template.spec.containers[0].env
 *    languages                    | template.spec.containers[0].env
 *    volumes                      | template.spec.volumes
 *    container                    | template.spec.containers[0]
 *
 * We will pre-propulate:
 *   - metadata
 *   - spec.selector
 *   - template.spec.securityContext.runAsUser
 *   - template.spec.securityContext.runAsNonRoot
 *   - template.spec.containers[0].name
 *   - template.spec.containers[0].ports
 *   - template.spec.containers[0].livenessProbe
 *   - template.spec.containers[0].readinessProbe
 *   - template.spec.containers[0].startupProbe
 *   - template.spec.containers[0].env (for CONFIG_SERVICE_XXX variables)
 */

func (r *IBMSecurityVerifyAccessReconciler) deploymentForVerifyAccess(
                    m *ibmv1.IBMSecurityVerifyAccess) *appsv1.Deployment {

    /*
     * The labels which are used in our deployment.
     */

    labels := map[string]string{
        "kind":            kindName,
        "app":             m.Name,
        "VerifyAccess_cr": m.Name,
    }

    falseVar := false
    trueVar  := true

    /*
     * The security context to be used.
     */

    isvaUser        := int64(6000)
    securityContext := m.Spec.Container.SecurityContext

    if securityContext == nil {
        securityContext = &corev1.SecurityContext {
            RunAsNonRoot: &trueVar,
            RunAsUser:    &isvaUser,
        }
    }

    /*
     * The port which is exported by the deployment.
     */

    ports := []corev1.ContainerPort {{
        Name:          "https",
        ContainerPort: 9443,
        Protocol:      corev1.ProtocolTCP,
    }}

    /*
     * The liveness, readiness and start-up probe definitions.
     */

    livenessProbe := m.Spec.Container.LivenessProbe

    if livenessProbe == nil {
        livenessProbe = &corev1.Probe {
            TimeoutSeconds:      3,
            Handler:             corev1.Handler {
                Exec: &corev1.ExecAction {
                    Command: []string{
                        "/sbin/health_check.sh",
                        "livenessProbe",
                    },
                },
            },
        }
    }

    readinessProbe := m.Spec.Container.ReadinessProbe

    if readinessProbe == nil {
        readinessProbe = &corev1.Probe {
            TimeoutSeconds:      3,
            Handler:             corev1.Handler {
                Exec: &corev1.ExecAction {
                    Command: []string{
                        "/sbin/health_check.sh",
                    },
                },
            },
        }
    }

    startupProbe := m.Spec.Container.StartupProbe

    if startupProbe == nil {
        startupProbe = &corev1.Probe {
            InitialDelaySeconds: 5,
            TimeoutSeconds:      20,
            FailureThreshold:    30,
            Handler:             corev1.Handler {
                Exec: &corev1.ExecAction {
                    Command: []string{
                        "/sbin/health_check.sh",
                        "startupProbe",
                    },
                },
            },
        }
    }

    /*
     * Set up the environment variables which are used to access the
     * embedded snapshot manager.
     */

    maxEnv      := 7
    env         := make([]corev1.EnvVar, 0, maxEnv)

    env = append(env, corev1.EnvVar {
        Name: "CONFIG_SERVICE_URL",
        ValueFrom: &corev1.EnvVarSource{
            SecretKeyRef: &corev1.SecretKeySelector{
                LocalObjectReference: corev1.LocalObjectReference{
                    Name: operatorName,
                },
                Key: urlFieldName,
                Optional: &falseVar,
            },
        },
    })

    env = append(env, corev1.EnvVar {
        Name: "CONFIG_SERVICE_USER_NAME",
        ValueFrom: &corev1.EnvVarSource{
            SecretKeyRef: &corev1.SecretKeySelector{
                LocalObjectReference: corev1.LocalObjectReference{
                    Name: operatorName,
                },
                Key: userFieldName,
                Optional: &falseVar,
            },
        },
    })

    env = append(env, corev1.EnvVar {
        Name: "CONFIG_SERVICE_USER_PWD",
        ValueFrom: &corev1.EnvVarSource{
            SecretKeyRef: &corev1.SecretKeySelector{
                LocalObjectReference: corev1.LocalObjectReference{
                    Name: operatorName,
                },
                Key: roPwdFieldName,
                Optional: &falseVar,
            },
        },
    })

    /*
     * Add the rest of the environment variables (if specified).
     */

    if m.Spec.SnapshotId != "" {
        env = append(env, corev1.EnvVar {
            Name: "SNAPSHOT_ID",
            Value: m.Spec.SnapshotId,
        })
    }

    if len(m.Spec.Fixpacks) > 0 {
        env = append(env, corev1.EnvVar {
            Name: "FIXPACKS",
            Value: strings.Join(m.Spec.Fixpacks,","),
        })
    }

    if m.Spec.Instance != "" {
        env = append(env, corev1.EnvVar {
            Name: "INSTANCE",
            Value: m.Spec.Instance,
        })
    }

    if m.Spec.Language != "" {
        env = append(env, corev1.EnvVar {
            Name: "LANG",
            Value: string(m.Spec.Language),
        })
    }

    /*
     * Set up the rest of the deployment descriptor.
     */

    dep := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      m.Name,
            Namespace: m.Namespace,
            Labels:    labels,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &m.Spec.Replicas,
            Selector: &metav1.LabelSelector{
                MatchLabels: labels,
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: labels,
                },
                Spec: corev1.PodSpec{
                    Volumes: m.Spec.Volumes,
                    Containers: []corev1.Container{{
                        Env:             m.Spec.Container.Env,
                        EnvFrom:         m.Spec.Container.EnvFrom,
                        Image:           m.Spec.Image,
                        ImagePullPolicy: m.Spec.Container.ImagePullPolicy,
                        LivenessProbe:   livenessProbe,
                        Name:            m.Name,
                        Ports:           ports,
                        ReadinessProbe:  readinessProbe,
                        Resources:       m.Spec.Container.Resources,
                        SecurityContext: securityContext,
                        StartupProbe:    startupProbe,
                        VolumeDevices:   m.Spec.Container.VolumeDevices,
                        VolumeMounts:    m.Spec.Container.VolumeMounts,
                    }},
                },
            },
        },
    }

    dep.Spec.Template.Spec.Containers[0].Env = append(
                dep.Spec.Template.Spec.Containers[0].Env, env...)

    // Set the VerifyAccess instance as the owner and controller
    ctrl.SetControllerReference(m, dep, r.Scheme)

    return dep
}

/*****************************************************************************/

/*
 * The following function is used to set up the controller with the Manager.
 */

func (r *IBMSecurityVerifyAccessReconciler) SetupWithManager(
                mgr ctrl.Manager) error {

    r.secretMutex = &sync.Mutex{}

    /*
     * Work out the namespace in which we are running.
     */

    r.localNamespace, _ = getLocalNamespace(r.Log)

    /*
     * Initialise and start the snapshot manager.
     */

    r.snapshotMgr = SnapshotMgr{
        config: mgr.GetConfig(),
        scheme: mgr.GetScheme(),
        log:    r.Log.WithName("SnapshotMgr"),
    }

    err := r.snapshotMgr.initialize()

    if err != nil {
        return err
    }

    go r.snapshotMgr.start()

    /*
     * Register our controller.
     */

    return ctrl.NewControllerManagedBy(mgr).
            For(&ibmv1.IBMSecurityVerifyAccess{}).
            Owns(&appsv1.Deployment{}).
            Complete(r)
}

/*****************************************************************************/


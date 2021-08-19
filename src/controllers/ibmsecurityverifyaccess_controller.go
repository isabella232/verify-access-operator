/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package controllers

/*****************************************************************************/

import (
    appsv1 "k8s.io/api/apps/v1"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/api/errors"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/types"

    "time"
    "context"

    "github.com/go-logr/logr"

    "k8s.io/apimachinery/pkg/runtime"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"

    ibmv1 "github.com/ibm-security/verify-access-operator/api/v1"
)

/*****************************************************************************/

/*
 * Global variables.
 */

var appName = "IBMSecurityVerifyAccess"

/*****************************************************************************/

/*
 * The IBMSecurityVerifyAccessReconciler structure reconciles an 
 * IBMSecurityVerifyAccess object.
 */

type IBMSecurityVerifyAccessReconciler struct {
    client.Client
    Log    logr.Logger
    Scheme *runtime.Scheme
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
    _ = r.Log.WithValues("ibmsecurityverifyaccess", req.NamespacedName)

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
             * A deployment does not already exist and so we create a new 
             * deployment.
             */

            dep := r.deploymentForVerifyAccess(verifyaccess)

            r.Log.Info("Creating a new Deployment", "Deployment.Namespace",
                                dep.Namespace, "Deployment.Name", dep.Name)

            err = r.Create(ctx, dep)

            if err != nil {
                r.Log.Error(err, "Failed to create the new Deployment",
                                "Deployment.Namespace", dep.Namespace,
                                "Deployment.Name", dep.Name)
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

    size := verifyaccess.Spec.Size

    if *found.Spec.Replicas != size {
        found.Spec.Replicas = &size
        err = r.Update(ctx, found)
        if err != nil {
            r.Log.Error(err, "Failed to update Deployment",
                                "Deployment.Namespace", found.Namespace,
                                "Deployment.Name", found.Name)

            r.setCondition(err, false, ctx, verifyaccess)
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
        r.Log.Error(err, "Failed to update the condition for the resource")

        return err
    }

    return nil
}

/*****************************************************************************/

/*
 * The following function is used to return a VerifyAccess Deployment object.
 */

func (r *IBMSecurityVerifyAccessReconciler) deploymentForVerifyAccess(
                    m *ibmv1.IBMSecurityVerifyAccess) *appsv1.Deployment {
    ls       := labelsForVerifyAccess(m.Name)
    replicas := m.Spec.Size

    dep := &appsv1.Deployment{
        ObjectMeta: metav1.ObjectMeta{
            Name:      m.Name,
            Namespace: m.Namespace,
            Labels:    ls,
        },
        Spec: appsv1.DeploymentSpec{
            Replicas: &replicas,
            Selector: &metav1.LabelSelector{
                MatchLabels: ls,
            },
            Template: corev1.PodTemplateSpec{
                ObjectMeta: metav1.ObjectMeta{
                    Labels: ls,
                },
                Spec: corev1.PodSpec{
                    Containers: []corev1.Container{{
                        Image:   "memcached:1.4.36-alpine",
                        Name:    "memcached",
                        Command: []string{"memcached", "-m=64", "-o", "modern", "-v"},
                        Ports: []corev1.ContainerPort{{
                            ContainerPort: 11211,
                            Name:          "memcached",
                        }},
                    }},
                },
            },
        },
    }

    // Set the VerifyAccess instance as the owner and controller
    ctrl.SetControllerReference(m, dep, r.Scheme)

    return dep
}

/*****************************************************************************/

/*
 * The following function returns the labels which are used when selecting
 * the resources belonging to the given VerifyAccess CR name.
 */

func labelsForVerifyAccess(name string) map[string]string {
    return map[string]string{"app": appName, "VerifyAccess_cr": name}
}

/*****************************************************************************/

/*
 * The following function is used to set up the controller with the Manager.
 */

func (r *IBMSecurityVerifyAccessReconciler) SetupWithManager(mgr ctrl.Manager) error {
    // start the snapshot manager
    go r.startSnapshotMgr(mgr)

    return ctrl.NewControllerManagedBy(mgr).
            For(&ibmv1.IBMSecurityVerifyAccess{}).
            Owns(&appsv1.Deployment{}).
            Complete(r)
}

/*****************************************************************************/

/*
 * This function is used to setup and start the snapshot manager server. 
 */

func (r *IBMSecurityVerifyAccessReconciler) startSnapshotMgr(mgr ctrl.Manager) {
    // Setup the snapshot manager.
    (&SnapshotMgr{
        config:  mgr.GetConfig(),
        scheme:  mgr.GetScheme(),
        log:     r.Log.WithValues("SnapshotMgr", "Server"),
        appName: appName,
    }).start()
}

/*****************************************************************************/


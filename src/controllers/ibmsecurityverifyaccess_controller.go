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

    "reflect"
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

    // Fetch the instance
    verifyaccess := &ibmv1.IBMSecurityVerifyAccess{}
    err          := r.Get(ctx, req.NamespacedName, verifyaccess)

    if err != nil {
        if errors.IsNotFound(err) {
            // The requested object was not found.  It could have been deleted 
            // after the reconcile request.  Owned objects are automatically 
            // garbage collected. For additional cleanup logic use finalizers.
            // Return and don't requeue
            r.Log.Info("VerifyAccess resource not found. " +
                                    "Ignoring since object must be deleted")
            return ctrl.Result{}, nil
        }

        // Error reading the object - requeue the request.
        r.Log.Error(err, "Failed to get VerifyAccess")

        return ctrl.Result{}, err
    }

    // Check if the deployment already exists, if not create a new one.
    found := &appsv1.Deployment{}
    err    = r.Get(
                    ctx,
                    types.NamespacedName{
                        Name:      verifyaccess.Name,
                        Namespace: verifyaccess.Namespace},
                    found)

    if err != nil && errors.IsNotFound(err) {
        // Define a new deployment
        dep := r.deploymentForVerifyAccess(verifyaccess)
        r.Log.Info("Creating a new Deployment", "Deployment.Namespace",
                                dep.Namespace, "Deployment.Name", dep.Name)

        err = r.Create(ctx, dep)

        if err != nil {
            r.Log.Error(err, "Failed to create new Deployment",
                                "Deployment.Namespace", dep.Namespace,
                                "Deployment.Name", dep.Name)

            return ctrl.Result{}, err
        }

        // Deployment created successfully - return and requeue.
        return ctrl.Result{Requeue: true}, nil

    } else if err != nil {
        r.Log.Error(err, "Failed to get Deployment")
        return ctrl.Result{}, err
    }

    // Ensure that the deployment size is the same as the spec.
    size := verifyaccess.Spec.Size

    if *found.Spec.Replicas != size {
        found.Spec.Replicas = &size
        err = r.Update(ctx, found)
        if err != nil {
            r.Log.Error(err, "Failed to update Deployment",
                                "Deployment.Namespace", found.Namespace,
                                "Deployment.Name", found.Name)
            return ctrl.Result{}, err
        }

        // Ask to requeue after 1 minute in order to give enough time for the
        // pods be created on the cluster side and the operand be able
        // to do the next update step accurately.
        return ctrl.Result{RequeueAfter: time.Minute}, nil
    }

    // Update the VerifyAccess status with the pod names and list the pods for 
    // this verifyaccess's deployment

    podList := &corev1.PodList{}

    listOpts := []client.ListOption {
        client.InNamespace(verifyaccess.Namespace),
        client.MatchingLabels(labelsForVerifyAccess(verifyaccess.Name)),
    }

    if err = r.List(ctx, podList, listOpts...); err != nil {
        r.Log.Error(err, "Failed to list pods", "VerifyAccess.Namespace",
                verifyaccess.Namespace, "VerifyAccess.Name", verifyaccess.Name)

        return ctrl.Result{}, err
    }

    podNames := getPodNames(podList.Items)

    // Update status.Nodes, if needed.

    if !reflect.DeepEqual(podNames, verifyaccess.Status.Nodes) {
        verifyaccess.Status.Nodes = podNames

        err := r.Status().Update(ctx, verifyaccess)

        if err != nil {
            r.Log.Error(err, "Failed to update VerifyAccess status")
            return ctrl.Result{}, err
        }
    }

    return ctrl.Result{}, nil
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
    return map[string]string{"app": "VerifyAccess", "VerifyAccess_cr": name}
}

/*****************************************************************************/

/*
 * The following function returns the pod names of the supplied array of pods.
 */

func getPodNames(pods []corev1.Pod) []string {
    var podNames []string

    for _, pod := range pods {
        podNames = append(podNames, pod.Name)
    }

    return podNames
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
        config: mgr.GetConfig(),
        log:    r.Log.WithValues("SnapshotMgr", "Server"),
    }).start()
}

/*****************************************************************************/


/*
 * Copyright contributors to the IBM Security Verify Access Operator project
 */

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IBMSecurityVerifyAccessSpec defines the desired state of an
// IBMSecurityVerifyAccess resource.
type IBMSecurityVerifyAccessSpec struct {
    // The name of the image which will be used in the deployment.
    Image string `json:"image"`

    //+kubebuilder:validation:Minimum=0
    //+kubebuilder:default=1
    // Size is the size of the memcached deployment
    // +optional
    Size int32 `json:"size"`

    //+kubebuilder:default=true
    // AutoRestart is a boolean which indicates whether the deployment should 
    // be restarted if a new snapshot is published
    // +optional
    AutoRestart bool `json:"autoRestart"`

    //+kubebuilder:default=published
    // SnapshotId is a string which is used to indicate the identifier of the
    // snapshot which should be used.  If no identifier is specified a default
    // snapshot of 'published' will be used.
    // +optional
    SnapshotId string `json:"snapshotId"`

    // Fixpacks is an array of strings which indicate the name of fixpacks
    // which should be installed in the deployment.  This corresponds to 
    // setting the FIXPACKS environment variable in the deployment itself.
    // +optional
    Fixpacks []string `json:"fixpacks,omitempty"`
}

// IBMSecurityVerifyAccessStatus defines the observed state of an
// IBMSecurityVerifyAccess resource.
type IBMSecurityVerifyAccessStatus struct {
    // Conditions is the list of status conditions for this resource
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IBMSecurityVerifyAccess is the Schema for the ibmsecurityverifyaccesses API.
//+kubebuilder:subresource:status
type IBMSecurityVerifyAccess struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   IBMSecurityVerifyAccessSpec   `json:"spec,omitempty"`
    Status IBMSecurityVerifyAccessStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IBMSecurityVerifyAccessList contains a list of IBMSecurityVerifyAccess
// resources.
type IBMSecurityVerifyAccessList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []IBMSecurityVerifyAccess `json:"items"`
}

func init() {
    SchemeBuilder.Register(
                &IBMSecurityVerifyAccess{}, &IBMSecurityVerifyAccessList{})
}


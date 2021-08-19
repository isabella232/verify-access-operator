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
    //+kubebuilder:validation:Minimum=0
    // Size is the size of the memcached deployment
    Size int32 `json:"size"`

    //+kubebuilder:default=true
    // AutoRestart is a boolean which indicates whether the deployment should 
    // be restarted if a new snapshot is published
    AutoRestart bool`json:"autoRestart"`
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


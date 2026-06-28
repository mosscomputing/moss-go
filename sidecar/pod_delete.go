package sidecar

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// realPodDeleter implements PodDeleter using client-go against the in-cluster
// service account (or an explicit kubeconfig for out-of-cluster testing).
type realPodDeleter struct {
	client kubernetes.Interface
}

// NewPodDeleter builds a PodDeleter from the sidecar config. When
// InClusterKubeConfig is true it uses the pod's service-account token
// (rest.InClusterConfig); otherwise it loads KubeconfigPath (or the
// KUBECONFIG env var).
func NewPodDeleter(cfg Config) (PodDeleter, error) {
	var restCfg *rest.Config
	var err error
	if cfg.InClusterKubeConfig {
		restCfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("sidecar: in-cluster kubeconfig: %w", err)
		}
	} else {
		loader := clientcmd.NewDefaultClientConfigLoadingRules()
		if cfg.KubeconfigPath != "" {
			loader.ExplicitPath = cfg.KubeconfigPath
		}
		restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loader, &clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("sidecar: kubeconfig: %w", err)
		}
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("sidecar: build kubernetes client: %w", err)
	}
	return &realPodDeleter{client: client}, nil
}

// DeletePod deletes the pod with gracePeriodSeconds:0 (force). A 404 is
// treated as success (the pod is already gone).
func (d *realPodDeleter) DeletePod(ctx context.Context, namespace, name string) error {
	grace := int64(0)
	deleteOpts := metav1.DeleteOptions{GracePeriodSeconds: &grace}
	err := d.client.CoreV1().Pods(namespace).Delete(ctx, name, deleteOpts)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// VerifyPodGone polls the pod until it returns 404/NotFound or the context
// deadline passes. Returns true if the pod is confirmed gone.
func (d *realPodDeleter) VerifyPodGone(ctx context.Context, namespace, name string) (bool, error) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := d.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
		}
	}
}

// listPod is a small helper retained for diagnostics/introspection by the
// watcher (e.g. confirming the pod exists before a delete attempt).
func (d *realPodDeleter) listPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return d.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	gcpcompute "cloud.google.com/go/compute/apiv1"
	"go.uber.org/zap/zapcore"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/giantswarm/capg-firewall-rule-operator/controllers"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/k8sclient"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/nat"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(capg.AddToScheme(scheme))
	utilruntime.Must(capi.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var gcpProject string
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var managementClusterName string
	var managementClusterNamespace string
	flag.StringVar(&gcpProject, "gcp-project", "",
		"The gcp project id where the firewall records will be created.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&managementClusterName, "management-cluster-name", "",
		"The name of the Cluster CR for the management cluster")
	flag.StringVar(&managementClusterNamespace, "management-cluster-namespace", "",
		"The namespace of the Cluster CR for the management cluster")

	opts := zap.Options{
		Development: true,
		TimeEncoder: zapcore.RFC3339TimeEncoder,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))

	ctrl.SetLogger(logger)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d632xu17.giantswarm.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	firewalls, err := gcpcompute.NewFirewallsRESTClient(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to create Cloud Firewall Rules client")
		os.Exit(1)
	}
	defer firewalls.Close()

	securityPolicies, err := gcpcompute.NewSecurityPoliciesRESTClient(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to create Cloud Security Policies client")
		os.Exit(1)
	}
	defer securityPolicies.Close()

	backendServices, err := gcpcompute.NewBackendServicesRESTClient(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to create Cloud Security Policies client")
		os.Exit(1)
	}
	defer backendServices.Close()

	addresses, err := gcpcompute.NewAddressesRESTClient(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to create Cloud Addresses client")
		os.Exit(1)
	}
	defer addresses.Close()

	routers, err := gcpcompute.NewRoutersRESTClient(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to create Cloud Routers client")
		os.Exit(1)
	}
	defer routers.Close()

	client := k8sclient.NewGCPCluster(mgr.GetClient())
	firewallClient := firewall.NewClient(firewalls)
	securityPolicyClient := security.NewClient(securityPolicies, backendServices)
	ipResolver := nat.NewIPResolver(client, addresses, routers)
	managementCluster := types.NamespacedName{
		Name:      managementClusterName,
		Namespace: managementClusterNamespace,
	}

	securityPolicyReconciler := security.NewPolicyReconciler(
		[]string{},
		managementCluster,
		securityPolicyClient,
		ipResolver,
	)
	firewallReconciler := firewall.NewRuleReconciler(firewallClient)

	controller := controllers.NewGCPClusterReconciler(
		client,
		firewallReconciler,
		securityPolicyReconciler,
	)

	err = controller.SetupWithManager(mgr)
	if err != nil {
		setupLog.Error(err, "failed to setup controller", "controller", "GCPCluster")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

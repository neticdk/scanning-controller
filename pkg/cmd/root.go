package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/bluele/gcache"
	"github.com/bombsimon/logrusr/v4"
	"github.com/neticdk/scanning-controller/pkg/controllers"
	"github.com/neticdk/scanning-controller/pkg/dependencies"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme = runtime.NewScheme()

	logLevel             int
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	clusterID            string
	clusterNRN           string
	depenciesServiceURL  string
	certFile             string
	keyFile              string

	rootCmd = &cobra.Command{
		Use:   "controller",
		Short: "controller to handle scanning of workloads in selected namespaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logrus.New()
			logger.SetLevel(logrus.Level(logLevel))
			ctrl.SetLogger(logrusr.New(logger))

			var setupLog = ctrl.Log.WithName("setup")

			cfg := ctrl.GetConfigOrDie()
			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme: scheme,
				Metrics: server.Options{
					BindAddress: metricsAddr,
				},
				HealthProbeBindAddress: probeAddr,
				LeaderElection:         enableLeaderElection,
				LeaderElectionID:       "e52ab890.netic.dk",
			})
			if err != nil {
				setupLog.Error(err, "unable to start manager")
				return err
			}

			//
			// Initialize Controllers
			//
			operatorConfig, err := etc.GetOperatorConfig()
			if err != nil {
				setupLog.Error(err, "unable to get operator config")
				return err
			}

			operatorNamespace, err := operatorConfig.GetOperatorNamespace()
			if err != nil {
				setupLog.Error(err, "unable to get operator namespace")
				return err
			}

			clientSet, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("constructing kube client: %w", err)
			}

			configManager := trivyoperator.NewConfigManager(clientSet, operatorNamespace)
			err = configManager.EnsureDefault(context.Background())
			if err != nil {
				return err
			}
			trivyOperatorConfig, err := configManager.Read(context.Background())
			if err != nil {
				return err
			}
			trivyOperatorConfig.Set(trivyoperator.KeyVulnerabilityScannerEnabled, "true")

			var limitChecker jobs.LimitChecker = jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
			var secretsReader kube.SecretsReader = kube.NewSecretsReader(mgr.GetClient())

			compatibleObjectMapper, err := kube.InitCompatibleMgr()
			if err != nil {
				return err
			}
			objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
			if err != nil {
				return err
			}

			var buildInfo trivyoperator.BuildInfo

			plugin, pluginContext, err := plugins.NewResolver().
				WithBuildInfo(buildInfo).
				WithNamespace(operatorNamespace).
				WithServiceAccountName(operatorConfig.ServiceAccount).
				WithConfig(trivyOperatorConfig).
				WithClient(mgr.GetClient()).
				WithObjectResolver(&objectResolver).
				GetVulnerabilityPlugin()
			if err != nil {
				return err
			}

			err = plugin.Init(pluginContext)
			if err != nil {
				return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
			}

			depSvc, err := dependencies.New(clusterID, clusterNRN, depenciesServiceURL, certFile, keyFile)
			if err != nil {
				return err
			}

			if err = (&controllers.WorkloadController{
				Logger:           ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
				Config:           operatorConfig,
				ConfigData:       trivyOperatorConfig,
				Client:           mgr.GetClient(),
				ObjectResolver:   objectResolver,
				LimitChecker:     limitChecker,
				SecretsReader:    secretsReader,
				Plugin:           plugin,
				PluginContext:    pluginContext,
				CacheSyncTimeout: *operatorConfig.ControllerCacheSyncTimeout,
				ServerHealthChecker: vcontroller.NewTrivyServerChecker(
					operatorConfig.TrivyServerHealthCheckCacheExpiration,
					gcache.New(1).LRU().Build(),
					vcontroller.NewHttpChecker()),
				SubmitScanJobChan: make(chan controllers.ScanJobRequest, operatorConfig.ConcurrentScanJobsLimit),
				ResultScanJobChan: make(chan controllers.ScanJobResult, operatorConfig.ConcurrentScanJobsLimit),
				DepService:        depSvc,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
			}

			logsReader := kube.NewLogsReader(clientSet)
			if err = (&controllers.ScanJobController{
				Client:         mgr.GetClient(),
				Config:         operatorConfig,
				ConfigData:     trivyOperatorConfig,
				LogsReader:     logsReader,
				ObjectResolver: objectResolver,
				DepService:     depSvc,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup vulnerabilityreport reporter: %w", err)
			}

			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				setupLog.Error(err, "unable to set up health check")
				return err
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				setupLog.Error(err, "unable to set up ready check")
				return err
			}

			setupLog.Info("starting manager")
			if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
				setupLog.Error(err, "problem running manager")
				return err
			}

			return nil
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	rootCmd.Flags().IntVarP(&logLevel, "v", "v", 4, "Log level verbosity 0 is only panic level and 6 is trace level")
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	rootCmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	rootCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	rootCmd.Flags().StringVar(&clusterID, "cluster-id", "", "Cluster identifier to be used when pushing scan results (FQDN)")
	rootCmd.Flags().StringVar(&clusterNRN, "cluster-nrn", "", "Cluster NRN identifier to be used when pushing scan results ")
	rootCmd.Flags().StringVar(&depenciesServiceURL, "dependencies-service", "", "Base url for dependencies service")
	rootCmd.Flags().StringVar(&certFile, "cert-file", "", "Path to file containing certificate chaing")
	rootCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing private key used to sign payload")
	_ = rootCmd.MarkFlagRequired("cluster-id")
	_ = rootCmd.MarkFlagRequired("dependencies-service")
}

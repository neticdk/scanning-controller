package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/operator/workload"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/go-logr/logr"
	"github.com/neticdk/scanning-controller/pkg/dependencies"
	batchv1 "k8s.io/api/batch/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// WorkloadController watches Kubernetes workloads and fires off scan jobs
type WorkloadController struct {
	logr.Logger
	etc.Config
	kube.ObjectResolver
	client.Client
	jobs.LimitChecker
	vulnerabilityreport.Plugin
	trivyoperator.PluginContext
	kube.SecretsReader
	trivyoperator.ConfigData
	ServerHealthChecker vcontroller.ServerHealthChecker
	SubmitScanJobChan   chan ScanJobRequest
	ResultScanJobChan   chan ScanJobResult
	CacheSyncTimeout    time.Duration
	DepService          dependencies.Service
}

// ScanJobResult encapsulate processing result and error
type ScanJobResult struct {
	Result ctrl.Result
	Error  error
}

// ScanJobRequest encapsulate workload and context for processing
type ScanJobRequest struct {
	Workload client.Object
	Context  context.Context
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=replicationcontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=exposedsecretreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=sbomreports,verbs=get;list;watch;create;update;patch;delete

// Manage scan jobs with image pull secrets
// kubebuilder:rbac:groups="",resources=secrets,verbs=create;update

func (r *WorkloadController) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	// Determine which Kubernetes workloads the controller will reconcile and add them to resources
	targetWorkloads := r.Config.GetTargetWorkloads()
	for _, tw := range targetWorkloads {
		var resource kube.Resource
		err := resource.GetWorkloadResource(tw, nil, r.ObjectResolver)
		if err != nil {
			return err
		}

		err = ctrl.NewControllerManagedBy(mgr).
			WithOptions(controller.Options{
				CacheSyncTimeout: r.CacheSyncTimeout,
			}).
			For(resource.ForObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate,
			)).
			Complete(r.reconcileWorkload(resource.Kind))
		if err != nil {
			return err
		}
	}

	// process scan jobs - sequentially
	go r.ProcessScanJob()

	return nil
}

func (r *WorkloadController) reconcileWorkload(workloadKind kube.Kind) reconcile.Func {
	r.Logger.WithValues("kind", workloadKind).V(1).Info("registering reconcile function")
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := ctrl.LoggerFrom(ctx, "kind", workloadKind, "name", req.NamespacedName)

		workloadRef := kube.ObjectRefFromKindAndObjectKey(workloadKind, req.NamespacedName)

		log.V(1).Info("Getting workload from cache")
		workloadObj, err := r.ObjectFromObjectRef(ctx, workloadRef)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				log.V(1).Info("Ignoring cached workload that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", workloadKind, err)
		}

		// Skip processing if it's a Pod controlled by a built-in K8s workload.
		if skip, err := workload.SkipProcessing(ctx, workloadObj, r.ObjectResolver,
			r.Config.VulnerabilityScannerScanOnlyCurrentRevisions, log, r.ConfigData.GetSkipResourceByLabels()); skip {
			return ctrl.Result{}, err
		}

		podSpec, err := kube.GetPodSpec(workloadObj)
		if err != nil {
			return ctrl.Result{}, err
		}

		hash := kube.ComputeHash(podSpec)
		log = log.WithValues("podSpecHash", hash)

		containerImages := kube.GetContainerImagesFromPodSpec(podSpec, r.GetSkipInitContainers())
		uptodate := true
		for name, ref := range containerImages {
			log.V(1).Info("check up to date", "name", name, "ref", ref)
			img, err := r.DepService.GetImage(ctx, ref)
			if err != nil {
				return ctrl.Result{}, err
			}

			if img == nil {
				uptodate = false
			} else {
				if !img.Central {
					uptodate = uptodate && img.LastScan.After(time.Now().Add(-12*time.Hour))
				}
			}
		}

		if uptodate {
			log.V(1).Info("All image scans was up to date")
			return ctrl.Result{}, nil
		}

		exists, job, err := r.hasActiveScanJob(ctx, workloadObj, hash)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking scan job: %w", err)
		}
		if exists {
			log.V(1).Info("Scan job already exists", "job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))
			return ctrl.Result{}, nil
		}

		if r.BuiltInTrivyServer {
			trivyServerAvaliable, err := r.ServerHealthChecker.TrivyServerAvaliable(r.GeTrivyServerURL())
			if err != nil {
				return ctrl.Result{}, err
			}
			if !trivyServerAvaliable {
				return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
			}
		}

		log.V(1).Info("Submitting a scan for the workload")
		r.SubmitScanJobChan <- ScanJobRequest{Workload: workloadObj, Context: ctx}

		scanJobResult := <-r.ResultScanJobChan // Wait for status starting scan job
		return scanJobResult.Result, scanJobResult.Error
	}
}

func (r *WorkloadController) ProcessScanJob() {
	for workloadRequest := range r.SubmitScanJobChan {
		log := r.Logger.WithValues("pre scan job processing for workload:", workloadRequest.Workload.GetName())
		limitExceeded, scanJobsCount, err := r.LimitChecker.Check(workloadRequest.Context)
		if err != nil {
			r.ResultScanJobChan <- ScanJobResult{Result: ctrl.Result{}, Error: err}
			continue
		}
		log.V(1).Info("Checking scan jobs limit", "count", scanJobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.V(1).Info("Pushing back scan job", "count", scanJobsCount, "retryAfter", r.ScanJobRetryAfter)
			r.ResultScanJobChan <- ScanJobResult{Result: ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, Error: nil}
			continue
		}
		err = r.submitScanJob(workloadRequest.Context, workloadRequest.Workload)
		r.ResultScanJobChan <- ScanJobResult{Result: ctrl.Result{}, Error: err}
	}
}

func (r *WorkloadController) hasActiveScanJob(ctx context.Context, owner client.Object, hash string) (bool, *batchv1.Job, error) {
	jobName := vulnerabilityreport.GetScanJobName(owner)
	job := &batchv1.Job{}
	err := r.Get(ctx, client.ObjectKey{Namespace: r.Config.Namespace, Name: jobName}, job)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("getting job from cache: %w", err)
	}
	if job.Labels[trivyoperator.LabelResourceSpecHash] == hash {
		return true, job, nil
	}
	return false, nil, nil
}

func (r *WorkloadController) submitScanJob(ctx context.Context, owner client.Object) error {
	log := r.Logger.WithValues("kind", owner.GetObjectKind().GroupVersionKind().Kind,
		"name", owner.GetName(), "namespace", owner.GetNamespace())
	var err error
	credentials := make(map[string]docker.Auth, 0)
	if r.AccessGlobalSecretsAndServiceAccount {
		privateRegistrySecrets, err := r.Config.GetPrivateRegistryScanSecretsNames()
		if err != nil {
			return err
		}
		pConfig, err := r.PluginContext.GetConfig()
		if err != nil {
			return err
		}
		multiSecretSupport := trivy.MultiSecretSupport(trivy.Config{PluginConfig: pConfig})
		credentials, err = r.CredentialsByServer(ctx, owner, privateRegistrySecrets, multiSecretSupport, true)
		if err != nil {
			return err
		}
	}

	scanJobTolerations, err := r.GetScanJobTolerations()
	if err != nil {
		return fmt.Errorf("getting scan job tolerations: %w", err)
	}

	scanJobAnnotations, err := r.GetScanJobAnnotations()
	if err != nil {
		return fmt.Errorf("getting scan job annotations: %w", err)
	}

	scanJobNodeSelector, err := r.GetScanJobNodeSelector()
	if err != nil {
		return fmt.Errorf("getting scan job nodeSelector: %w", err)
	}

	scanJobSecurityContext, err := r.GetScanJobPodSecurityContext()
	if err != nil {
		return fmt.Errorf("getting scan job podSecurityContext: %w", err)
	}

	scanJobContainerSecurityContext, err := r.GetScanJobContainerSecurityContext()
	if err != nil {
		return fmt.Errorf("getting scan job [container] securityContext: %w", err)
	}

	scanJobPodTemplateLabels, err := r.GetScanJobPodTemplateLabels()
	if err != nil {
		return fmt.Errorf("getting scan job template labels: %w", err)
	}

	scanJobPodPriorityClassName, err := r.GetScanJobPodPriorityClassName()
	if err != nil {
		return fmt.Errorf("getting scan job priority class name: %w", err)
	}

	scanJob, secrets, err := vulnerabilityreport.NewScanJobBuilder().
		WithPlugin(r.Plugin).
		WithPluginContext(r.PluginContext).
		WithTimeout(r.Config.ScanJobTimeout).
		WithTTL(r.Config.ScanJobTTL).
		WithObject(owner).
		WithTolerations(scanJobTolerations).
		WithAnnotations(scanJobAnnotations).
		WithNodeSelector(scanJobNodeSelector).
		WithPodSecurityContext(scanJobSecurityContext).
		WithSecurityContext(scanJobContainerSecurityContext).
		WithSkipInitContainers(r.GetSkipInitContainers()).
		WithPodTemplateLabels(scanJobPodTemplateLabels).
		WithCredentials(credentials).
		WithPodPriorityClassName(scanJobPodPriorityClassName).
		Get()
	if err != nil {
		if errors.Is(err, kube.ErrReplicaSetNotFound) || errors.Is(err, kube.ErrNoRunningPods) ||
			errors.Is(err, kube.ErrUnSupportedKind) {
			log.V(1).Info("ignoring vulnerability scan", "reason", err)
			return nil
		}
		return fmt.Errorf("constructing scan job: %w", err)
	}

	for _, secret := range secrets {
		err = r.Client.Create(ctx, secret)
		if err != nil {
			if k8sapierror.IsAlreadyExists(err) {
				return nil
			}
			return fmt.Errorf("creating secret used by scan job failed: %s: %w", secret.Namespace+"/"+secret.Name, err)
		}
	}

	log = log.WithValues("podSpecHash", scanJob.Labels[trivyoperator.LabelResourceSpecHash])

	log.V(1).Info("Creating scan job for the workload")
	err = r.Client.Create(ctx, scanJob)
	if err != nil {
		if k8sapierror.IsAlreadyExists(err) {
			// TODO Delete secrets that were created in the previous step. Alternatively we can delete them on schedule.
			return nil
		}
		return fmt.Errorf("creating scan job failed: %s: %w", scanJob.Namespace+"/"+scanJob.Name, err)
	}

	for _, secret := range secrets {
		err = controllerutil.SetOwnerReference(scanJob, secret, r.Client.Scheme())
		if err != nil {
			return fmt.Errorf("setting owner reference: %w", err)
		}
		err := r.Client.Update(ctx, secret)
		if err != nil {
			return fmt.Errorf("setting owner reference of secret used by scan job failed: %s: %w", secret.Namespace+"/"+secret.Name, err)
		}
	}

	return nil
}

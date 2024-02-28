package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	op "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	ty "github.com/aquasecurity/trivy/pkg/types"
	"github.com/docker/distribution/reference"
	"github.com/neticdk/scanning-controller/pkg/dependencies"
	"go.uber.org/multierr"
	batchv1 "k8s.io/api/batch/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type ScanJobController struct {
	client.Client
	trivyoperator.ConfigData
	etc.Config
	kube.LogsReader
	kube.ObjectResolver
	DepService dependencies.Service
}

func (r *ScanJobController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	job := &batchv1.Job{}
	err := r.Client.Get(ctx, req.NamespacedName, job)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			log.V(1).Info("Ignoring cached job that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
	}

	if len(job.Status.Conditions) == 0 {
		log.V(1).Info("Ignoring Job without conditions")
		return ctrl.Result{}, nil
	}

	switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
	case batchv1.JobComplete:
		err = r.processCompleteScanJob(ctx, job)
	case batchv1.JobFailed:
		err = r.processFailedScanJob(ctx, job)
	default:
		err = fmt.Errorf("unrecognized scan job condition: %v", jobCondition)
	}

	return ctrl.Result{}, err
}

func (r *ScanJobController) processCompleteScanJob(ctx context.Context, job *batchv1.Job) error {
	log := log.FromContext(ctx)

	ownerRef, err := kube.ObjectRefFromObjectMeta(job.ObjectMeta)
	if err != nil {
		return fmt.Errorf("getting owner ref from scan job metadata: %w", err)
	}

	owner, err := r.ObjectFromObjectRef(ctx, ownerRef)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			log.V(1).Info("Report owner must have been deleted", "owner", ownerRef)
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting object from object ref: %w", err)
	}

	containerImages, err := kube.GetContainerImagesFromJob(job)
	if err != nil {
		return fmt.Errorf("getting container images: %w", err)
	}

	podSpecHash, ok := job.Labels[trivyoperator.LabelResourceSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", trivyoperator.LabelResourceSpecHash)
	}

	log = log.WithValues("kind", owner.GetObjectKind().GroupVersionKind().Kind,
		"name", owner.GetName(), "namespace", owner.GetNamespace(), "podSpecHash", podSpecHash)

	log.V(1).Info("Job complete")

	var merr error
	for containerName, containerImage := range containerImages {
		res, err := r.processScanJobResults(ctx, job, containerName, containerImage, owner)
		if err != nil {
			merr = multierr.Append(merr, err)
		} else {
			owner, err := resolveOwnerChain(ctx, &r.ObjectResolver, owner)
			if err != nil {
				merr = multierr.Append(merr, err)
				continue
			}
			res.Workload = dependencies.RefFromKind(owner)
			err = r.DepService.PushScan(ctx, containerImage, res)
			if err != nil {
				merr = multierr.Append(merr, err)
			}
		}
	}
	if merr != nil {
		return merr
	}

	log.V(1).Info("Deleting complete scan job", "name", owner.GetName(), "namespace", owner.GetNamespace())
	return r.deleteJob(ctx, job)
}

func (r *ScanJobController) processScanJobResults(ctx context.Context, job *batchv1.Job, containerName, containerImage string, owner client.Object) (*dependencies.ScanResult, error) {
	log := log.FromContext(ctx)

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil, nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return nil, r.deleteJob(ctx, job)
		}
		return nil, fmt.Errorf("getting logs for pod %q: %w", job.Namespace+"/"+job.Name, err)
	}

	defer func() {
		if err := logsStream.Close(); err != nil {
			log.V(1).Error(err, "could not close log stream")
		}
	}()

	return r.processLogStream(ctx, logsStream)
}

func (r *ScanJobController) processLogStream(ctx context.Context, stream io.ReadCloser) (*dependencies.ScanResult, error) {
	if r.ConfigData.CompressLogs() {
		var err error
		stream, err = utils.ReadCompressData(stream)
		if err != nil {
			return nil, err
		}
	}

	var reports ty.Report
	err := json.NewDecoder(stream).Decode(&reports)
	if err != nil {
		return nil, err
	}

	vuln, _ := convertTrivyReport(ctx, &reports)
	bom, _ := cyclonedx.NewMarshaler("").Marshal(reports)

	sha := GetHashFromRepoDigest(reports.Metadata.RepoDigests, reports.ArtifactName)

	scan := &dependencies.ScanResult{
		Sha:             sha,
		Vulnerabilities: vuln,
		BOM:             bom,
	}

	return scan, nil
}

// GetHashFromRepoDigest implements same logic as kubeclarity
// https://github.com/openclarity/kubeclarity/blob/main/shared/pkg/utils/image_helper/image_helper.go#L43
func GetHashFromRepoDigest(repoDigests []string, imageName string) string {
	if len(repoDigests) == 0 {
		return ""
	}

	normalizedName, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return ""
	}
	familiarName := reference.FamiliarName(normalizedName)
	// iterating over RepoDigests and use RepoDigest which match to imageName
	for _, repoDigest := range repoDigests {
		normalizedRepoDigest, err := reference.ParseNormalizedNamed(repoDigest)
		if err != nil {
			return ""
		}
		// RepoDigests can be different based on the registry
		//        ],
		//        "RepoDigests": [
		//            "debian@sha256:2906804d2a64e8a13a434a1a127fe3f6a28bf7cf3696be4223b06276f32f1f2d",
		//            "poke/debian@sha256:a4c378901a2ba14fd331e96a49101556e91ed592d5fd68ba7405fdbf9b969e61",
		//            "poke/testdebian@sha256:a4c378901a2ba14fd331e96a49101556e91ed592d5fd68ba7405fdbf9b969e61"
		//        ],
		// Check which RegoDigest should be used
		if reference.FamiliarName(normalizedRepoDigest) == familiarName {
			return normalizedRepoDigest.(reference.Digested).Digest().Encoded() // nolint:forcetypeassert
		}
	}
	return ""
}

func (r *ScanJobController) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := log.FromContext(ctx)
	log.Info("job failed")
	statuses, err := r.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, scanJob)
		}
		return err
	}
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	log.V(1).Info("Deleting failed scan job")
	return r.deleteJob(ctx, scanJob)
}

func (r *ScanJobController) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting job: %w", err)
	}
	return nil
}

func resolveOwnerChain(ctx context.Context, resolver *kube.ObjectResolver, obj client.Object) (client.Object, error) {
	owner := metav1.GetControllerOf(obj)
	if owner != nil {
		o := &unstructured.Unstructured{}
		o.SetAPIVersion(owner.APIVersion)
		o.SetKind(owner.Kind)
		err := resolver.Client.Get(ctx, client.ObjectKey{Namespace: obj.GetNamespace(), Name: owner.Name}, o)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				return nil, fmt.Errorf("owner has been deleted: %w", err)
			}
			return nil, fmt.Errorf("getting object from object ref: %w", err)
		}
		return resolveOwnerChain(ctx, resolver, o)
	}
	return obj, nil
}

func (r *ScanJobController) SetupWithManager(mgr ctrl.Manager) error {
	var predicates []predicate.Predicate
	if !r.ConfigData.VulnerabilityScanJobsInSameNamespace() {
		predicates = append(predicates, op.InNamespace(r.Config.Namespace))
	}
	predicates = append(predicates, op.ManagedByTrivyOperator, op.IsVulnerabilityReportScan, op.JobHasAnyCondition)
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(predicates...)).
		Complete(r)
}

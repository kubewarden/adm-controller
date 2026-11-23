package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/k8s"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/policies"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/report"
	"golang.org/x/sync/semaphore"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

const httpClientTimeout = 10 * time.Second

// reportNameSet is a concurrency-safe set of report names (resource UIDs)
// collected while auditing resources in parallel. It records the reports that
// were created or patched during the current scan run, so that the garbage
// collection step can delete only the reports that are NOT part of this run.
type reportNameSet struct {
	mu    sync.Mutex
	names sets.Set[string]
}

func newReportNameSet() *reportNameSet {
	return &reportNameSet{names: sets.New[string]()}
}

func (r *reportNameSet) insert(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names.Insert(name)
}

// snapshot returns a copy of the collected names, safe to use after the audit
// goroutines have finished.
func (r *reportNameSet) snapshot() sets.Set[string] {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names.Clone()
}

// Scanner verifies that existing resources don't violate any of the policies.
type Scanner struct {
	policiesClient *policies.Client
	k8sClient      *k8s.Client
	reportStore    report.Store
	// http client used to make requests against the Policy Server
	httpClient               http.Client
	outputScan               bool
	disableStore             bool
	parallelNamespacesAudits int
	parallelResourcesAudits  int
	parallelPoliciesAudits   int
	logger                   *slog.Logger
	reportKind               report.CrdKind
}

// NewScanner creates a new scanner
// If insecureClient is false, it will read the caCertFile and add it to the in-app
// cert trust store. This gets used by the httpClient when connection to
// PolicyServers endpoints.
func NewScanner(config Config) (*Scanner, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Get the SystemCertPool to build an in-app cert pool from it
	// Continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	logger := config.Logger.With("component", "scanner")
	if config.TLS.CAFile != "" {
		caCert, err := os.ReadFile(config.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q with CA cert: %w", config.TLS.CAFile, err)
		}
		// Append our cert to the in-app cert pool
		if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("failed to append cert to in-app RootCAs trust store")
		}
		logger.Debug("appended cert file to in-app RootCAs trust store", slog.String("ca-cert", config.TLS.CAFile))
	}

	tlsConfig.RootCAs = rootCAs

	if config.TLS.ClientCertFile != "" && config.TLS.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLS.ClientCertFile, config.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		logger.Debug("appended cert file to in-app RootCAs trust store",
			slog.String("client-cert", config.TLS.ClientCertFile),
			slog.String("client-key", config.TLS.ClientKeyFile))

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.TLS.Insecure {
		logger.Warn("connecting to PolicyServers endpoints without validating TLS connection")
	}
	tlsConfig.InsecureSkipVerify = config.TLS.Insecure

	httpClient := *http.DefaultClient
	httpClient.Timeout = httpClientTimeout
	httpClient.Transport = http.DefaultTransport
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("failed to build httpClient: failed http.Transport type assertion")
	}

	transport.TLSClientConfig = tlsConfig

	// By default, the http client reuses connections. This causes
	// scaling issues when a PolicyServer instance is backed by multiple
	// replicas. In this scanerio, the requests are sent to the same
	// PolicyServer Pod, causing the load to be unevenly distributed.
	// To avoid this, we disable keep-alives, which ensures a
	// new connection is created for each evaluation request.
	transport.DisableKeepAlives = true

	return &Scanner{
		policiesClient:           config.PoliciesClient,
		k8sClient:                config.K8sClient,
		reportStore:              config.ReportStore,
		httpClient:               httpClient,
		outputScan:               config.OutputScan,
		disableStore:             config.DisableStore,
		parallelNamespacesAudits: config.Parallelization.ParallelNamespacesAudits,
		parallelResourcesAudits:  config.Parallelization.ParallelResourcesAudits,
		parallelPoliciesAudits:   config.Parallelization.PoliciesAudits,
		logger:                   logger,
		reportKind:               config.ReportKind,
	}, nil
}

// ScanNamespace scans resources for a given namespace.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanNamespace(ctx context.Context, nsName, runUID string) error {
	s.logger.InfoContext(ctx, "namespace scan started",
		slog.String("namespace", nsName),
		slog.String("RunUID", runUID),
		slog.Int("parallel-resources-audits", s.parallelResourcesAudits))

	namespace, err := s.k8sClient.GetNamespace(ctx, nsName)
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", nsName, err)
	}
	policies, err := s.policiesClient.GetPoliciesByNamespace(ctx, namespace)
	if err != nil {
		return fmt.Errorf("failed to obtain auditable policies for namespace %s: %w", nsName, err)
	}

	s.logger.InfoContext(ctx, "policy count",
		slog.String("namespace", nsName),
		slog.Int("policies-to-evaluate", policies.PolicyNum),
		slog.Int("policies-skipped", policies.SkippedNum),
		slog.Int("policies-errored", policies.ErroredNum))

	if len(policies.PoliciesByGVR) == 0 {
		// No policy targets any resource in this namespace, so no report can
		// have been written during this run: every kubewarden-managed report
		// found is necessarily stale and can be deleted in a single call,
		// instead of listing and comparing against an (empty) write-set.
		s.deleteAllNamespaceReports(ctx, nsName, runUID)
		s.logger.InfoContext(ctx, "Namespaced resources scan finished")
		return nil
	}

	semaphore := semaphore.NewWeighted(int64(s.parallelResourcesAudits))
	var workers sync.WaitGroup
	keptReports := newReportNameSet()

	for gvr, pols := range policies.PoliciesByGVR {
		pager := s.k8sClient.GetResources(gvr, nsName)

		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return errors.New("failed to convert runtime.Object to *unstructured.Unstructured")
			}

			acquireErr := semaphore.Acquire(ctx, 1)
			if acquireErr != nil {
				return fmt.Errorf("failed to acquire the permission to audit resource: %w", acquireErr)
			}
			workers.Add(1)
			policiesToAudit := pols

			go func() {
				defer semaphore.Release(1)
				defer workers.Done()

				if auditErr := s.auditResource(ctx, policiesToAudit, *resource, runUID, policies.SkippedNum, policies.ErroredNum, keptReports); auditErr != nil {
					s.logger.ErrorContext(ctx, "error auditing resource",
						slog.String("error", auditErr.Error()),
						slog.String("RunUID", runUID))
				}
			}()
			return nil
		})
		if err != nil {
			// If we fail to get the resources, we log the error inside the pager function
			// and continue with the next GVR. Otherwise, the scan would stop
			// and not audit any other resources.
			s.logger.WarnContext(ctx, "Failed to list resources",
				slog.String("error", err.Error()),
				slog.String("resource-GVK", gvr.String()),
				slog.String("ns", nsName))
			continue
		}
	}
	workers.Wait()

	s.deleteStaleNamespaceReports(ctx, nsName, runUID, keptReports)
	s.logger.InfoContext(ctx, "Namespaced resources scan finished")
	return nil
}

// deleteAllNamespaceReports deletes every kubewarden-managed report in
// nsName, unless the store is disabled. Used when no policy targets any
// resource in the namespace, so no report can have been written this run and
// every managed report found is necessarily stale.
func (s *Scanner) deleteAllNamespaceReports(ctx context.Context, nsName, runUID string) {
	if s.disableStore {
		s.logger.InfoContext(ctx, "store disabled, skipping deletion of managed reports",
			slog.String("namespace", nsName))
		return
	}
	s.logger.InfoContext(ctx, "no auditable policies for namespace, deleting all managed reports",
		slog.String("namespace", nsName))
	if deleteErr := s.reportStore.DeleteAllReports(ctx, nsName); deleteErr != nil {
		s.logger.ErrorContext(ctx, "error deleting old reports",
			slog.String("error", deleteErr.Error()),
			slog.String("RunUID", runUID))
	}
}

// deleteStaleNamespaceReports deletes the kubewarden-managed reports in
// nsName that are not part of keptReports, unless the store is disabled.
func (s *Scanner) deleteStaleNamespaceReports(ctx context.Context, nsName, runUID string, keptReports *reportNameSet) {
	if s.disableStore {
		s.logger.InfoContext(ctx, "store disabled, skipping deletion of managed reports",
			slog.String("namespace", nsName))
		return
	}
	if deleteErr := s.reportStore.DeleteOldReports(ctx, keptReports.snapshot(), nsName); deleteErr != nil {
		s.logger.ErrorContext(ctx, "error deleting old reports",
			slog.String("error", deleteErr.Error()),
			slog.String("RunUID", runUID))
	}
}

// ScanAllNamespaces scans resources for all namespaces, except the ones in the skipped list.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces(ctx context.Context, runUID string) error {
	s.logger.InfoContext(ctx, "all-namespaces scan started",
		slog.Group("dict",
			slog.Int("parallel-namespaces-audits", s.parallelNamespacesAudits)))
	nsList, err := s.k8sClient.GetAuditedNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("error scanning all namespaces: %w", err)
	}
	semaphore := semaphore.NewWeighted(int64(s.parallelNamespacesAudits))
	var workers sync.WaitGroup
	var errLock sync.Mutex

	for _, namespace := range nsList.Items {
		acquireErr := semaphore.Acquire(ctx, 1)
		if acquireErr != nil {
			workers.Wait()
			return fmt.Errorf("failed to acquire the permission to audit namespace: %w", acquireErr)
		}
		workers.Add(1)
		namespaceName := namespace.Name

		go func() {
			defer semaphore.Release(1)
			defer workers.Done()

			if e := s.ScanNamespace(ctx, namespaceName, runUID); e != nil {
				s.logger.ErrorContext(ctx, "error scanning namespace", slog.String("error", e.Error()), slog.String("ns", namespaceName))
				errLock.Lock()
				err = errors.Join(err, e)
				errLock.Unlock()
			}
		}()
	}
	workers.Wait()

	s.logger.InfoContext(ctx, "all-namespaces scan finished")

	if err != nil {
		return fmt.Errorf("error scanning all namespaces: %w", err)
	}
	return nil
}

// ScanClusterWideResources scans all cluster wide resources.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanClusterWideResources(ctx context.Context, runUID string) error {
	s.logger.InfoContext(ctx, "clusterwide resources scan started", slog.String("RunUID", runUID))

	policies, err := s.policiesClient.GetClusterWidePolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain cluster auditable policies: %w", err)
	}

	s.logger.InfoContext(ctx, "cluster admission policies count",
		slog.Int("policies-to-evaluate", policies.PolicyNum),
		slog.Int("policies-skipped", policies.SkippedNum),
		slog.Int("policies-errored", policies.ErroredNum),
		slog.Int("parallel-resources-audits", s.parallelResourcesAudits))

	if len(policies.PoliciesByGVR) == 0 {
		// No cluster-wide policy targets any resource, so no cluster report can
		// have been written during this run: every kubewarden-managed
		// ClusterReport found is necessarily stale and can be deleted in a
		// single call, instead of listing and comparing against an (empty)
		// write-set.
		s.deleteAllClusterReports(ctx, runUID)
		s.logger.InfoContext(ctx, "Cluster-wide resources scan finished")
		return nil
	}

	semaphore := semaphore.NewWeighted(int64(s.parallelResourcesAudits))
	var workers sync.WaitGroup
	keptReports := newReportNameSet()

	for gvr, pols := range policies.PoliciesByGVR {
		pager := s.k8sClient.GetResources(gvr, "")
		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return errors.New("failed to convert runtime.Object to *unstructured.Unstructured")
			}

			workers.Add(1)
			acquireErr := semaphore.Acquire(ctx, 1)
			if acquireErr != nil {
				return fmt.Errorf("failed to acquire the permission to audit a resource: %w", acquireErr)
			}
			policiesToAudit := pols

			go func() {
				defer semaphore.Release(1)
				defer workers.Done()

				s.auditClusterResource(ctx, policiesToAudit, *resource, runUID, policies.SkippedNum, policies.ErroredNum, keptReports)
			}()

			return nil
		})
		if err != nil {
			// If we fail to get the resources, we log the error inside the pager function
			// and continue with the next GVR. Otherwise, the scan would stop
			// and not audit any other resources.
			s.logger.WarnContext(ctx, "Failed to list resources",
				slog.String("error", err.Error()),
				slog.String("resource-GVK", gvr.String()))
			continue
		}
	}

	workers.Wait()

	s.deleteStaleClusterReports(ctx, runUID, keptReports)
	s.logger.InfoContext(ctx, "Cluster-wide resources scan finished")
	return nil
}

// deleteAllClusterReports deletes every kubewarden-managed ClusterReport,
// unless the store is disabled. Used when no cluster-wide policy targets any
// resource, so no report can have been written this run and every managed
// report found is necessarily stale.
func (s *Scanner) deleteAllClusterReports(ctx context.Context, runUID string) {
	if s.disableStore {
		s.logger.InfoContext(ctx, "store disabled, skipping deletion of managed ClusterReports")
		return
	}
	s.logger.InfoContext(ctx, "no cluster-wide auditable policies, deleting all managed ClusterReports")
	if deleteErr := s.reportStore.DeleteAllClusterReports(ctx); deleteErr != nil {
		s.logger.ErrorContext(ctx, "error deleting old ClusterReports",
			slog.String("error", deleteErr.Error()),
			slog.String("RunUID", runUID))
	}
}

// deleteStaleClusterReports deletes the kubewarden-managed ClusterReports
// that are not part of keptReports, unless the store is disabled.
func (s *Scanner) deleteStaleClusterReports(ctx context.Context, runUID string, keptReports *reportNameSet) {
	if s.disableStore {
		s.logger.InfoContext(ctx, "store disabled, skipping deletion of managed ClusterReports")
		return
	}
	if deleteErr := s.reportStore.DeleteOldClusterReports(ctx, keptReports.snapshot()); deleteErr != nil {
		s.logger.ErrorContext(ctx, "error deleting old ClusterReports",
			slog.String("error", deleteErr.Error()),
			slog.String("RunUID", runUID))
	}
}

type policyAuditResult struct {
	policy                  policiesv1.Policy
	admissionReviewResponse *admissionv1.AdmissionReview
	errored                 bool
}

//gocognit:ignore
func (s *Scanner) auditResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, runUID string, skippedPoliciesNum, erroredPoliciesNum int, keptReports *reportNameSet) error {
	s.logger.InfoContext(ctx, "audit resource",
		slog.String("resource", resource.GetName()),
		slog.Int("policies-to-evaluate", len(policies)),
		slog.Int("parallel-policies-audit", s.parallelPoliciesAudits))

	semaphore := semaphore.NewWeighted(int64(s.parallelPoliciesAudits))
	var workers sync.WaitGroup
	auditResults := make(chan policyAuditResult, len(policies))

	for _, policyToUse := range policies {
		err := semaphore.Acquire(ctx, 1)
		if err != nil {
			return fmt.Errorf("failed to acquire the permission to audit a resource: %w", err)
		}
		workers.Add(1)

		url := policyToUse.PolicyServer
		policy := policyToUse.Policy

		go func() {
			defer semaphore.Release(1)
			defer workers.Done()

			matches, matchErr := policyMatches(policy, resource)
			if matchErr != nil {
				s.logger.ErrorContext(ctx, "error matching policy to resource", slog.String("error", matchErr.Error()))
			}

			if !matches {
				return
			}

			admissionReviewRequest := newAdmissionReview(resource)
			admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)
			errored := false

			if responseErr != nil {
				errored = true
				// log responseErr, will end in PolicyReportResult too
				s.logger.ErrorContext(ctx, "error sending AdmissionReview to PolicyServer",
					slog.String("error", responseErr.Error()),
					slog.Group("response",
						slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName())))
			} else if admissionReviewResponse.Response.Result != nil &&
				admissionReviewResponse.Response.Result.Code == 500 {
				errored = true
				// log Result.Message, will end in PolicyReportResult too
				s.logger.ErrorContext(ctx, "error evaluating Policy in PolicyServer", slog.String("error", errors.New(admissionReviewResponse.Response.Result.Message).Error()),
					slog.Group("response",
						slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName())))
			}

			if !errored {
				s.logger.DebugContext(ctx, "audit review response",
					slog.Group("response",
						slog.String("uid", string(admissionReviewResponse.Response.UID)),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName()),
						slog.Bool("allowed", admissionReviewResponse.Response.Allowed)))
			}

			auditResults <- policyAuditResult{
				policy,
				admissionReviewResponse,
				errored,
			}
		}()
	}
	workers.Wait()
	close(auditResults)

	policyReport := report.NewReportOfKind(s.reportKind, runUID, resource)
	policyReport.SetErrorPolicies(erroredPoliciesNum)
	policyReport.SetSkipPolicies(skippedPoliciesNum)
	for res := range auditResults {
		policyReport.AddResult(res.policy, res.admissionReviewResponse, res.errored)
	}

	if s.outputScan {
		policyReportJSON, err := json.Marshal(policyReport)
		if err != nil {
			s.logger.ErrorContext(ctx, "error while marshalling PolicyReport to JSON, skipping output scan", slog.String("error", err.Error()))
		}

		s.logger.InfoContext(ctx, "PolicyReport summary", slog.String("report", string(policyReportJSON)))
	}

	if !s.disableStore {
		err := s.reportStore.CreateOrPatchReport(ctx, policyReport)
		if err != nil {
			s.logger.ErrorContext(ctx, "error adding PolicyReport to store.", slog.String("error", err.Error()))
		} else {
			// Record the report as part of this run so the garbage collection
			// step does not delete it. The report name is the resource UID.
			keptReports.insert(string(resource.GetUID()))
		}
	}
	return nil
}

func (s *Scanner) auditClusterResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, runUID string, skippedPoliciesNum, erroredPoliciesNum int, keptReports *reportNameSet) {
	s.logger.InfoContext(ctx, "audit clusterwide resource",
		slog.String("resource", resource.GetName()),
		slog.Int("policies-to-evaluate", len(policies)))

	clusterReport := report.NewClusterReportOfKind(s.reportKind, runUID, resource)
	clusterReport.SetSkipPolicies(skippedPoliciesNum)
	clusterReport.SetErrorPolicies(erroredPoliciesNum)
	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		matches, err := policyMatches(policy, resource)
		if err != nil {
			s.logger.ErrorContext(ctx, "error matching policy to resource", slog.String("error", err.Error()))
		}

		if !matches {
			continue
		}

		admissionReviewRequest := newAdmissionReview(resource)
		admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)
		errored := false

		if responseErr != nil {
			errored = true
			// log error, will end in ClusterPolicyReportResult too
			s.logger.ErrorContext(ctx, "error sending AdmissionReview to PolicyServer", slog.String("error", responseErr.Error()),
				slog.Group("response",
					slog.String("admissionRequest name", admissionReviewRequest.Request.Name),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName())))
		} else if admissionReviewResponse.Response.Result != nil &&
			admissionReviewResponse.Response.Result.Code == 500 {
			errored = true
			// log Result.Message, will end in PolicyReportResult too
			s.logger.ErrorContext(ctx, "error evaluating Policy in PolicyServer", slog.String("error", errors.New(admissionReviewResponse.Response.Result.Message).Error()),
				slog.Group("response",
					slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName())))
		}

		if !errored {
			s.logger.DebugContext(ctx, "audit review response",
				slog.Group("response",
					slog.String("uid", string(admissionReviewResponse.Response.UID)),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName()),
					slog.Bool("allowed", admissionReviewResponse.Response.Allowed)))
		}

		clusterReport.AddResult(policy, admissionReviewResponse, errored)
	}

	if s.outputScan {
		clusterPolicyReportJSON, err := json.Marshal(clusterReport)
		if err != nil {
			s.logger.ErrorContext(ctx, "error while marshalling ClusterPolicyReport to JSON, skipping output scan", slog.String("error", err.Error()))
		}

		s.logger.InfoContext(ctx, "ClusterPolicyReport summary", slog.Any("report", clusterPolicyReportJSON))
	}

	if !s.disableStore {
		err := s.reportStore.CreateOrPatchClusterReport(ctx, clusterReport)
		if err != nil {
			s.logger.ErrorContext(ctx, "error adding ClusterPolicyReport to store", slog.String("error", err.Error()))
		} else {
			// Record the report as part of this run so the garbage collection
			// step does not delete it. The report name is the resource UID.
			keptReports.insert(string(resource.GetUID()))
		}
	}
}

func policyMatches(policy policiesv1.Policy, resource unstructured.Unstructured) (bool, error) {
	if policy.GetObjectSelector() == nil {
		return true, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(policy.GetObjectSelector())
	if err != nil {
		return false, fmt.Errorf("failed to convert label selector from policy object selector: %w", err)
	}

	labels := labels.Set(resource.GetLabels())
	if !selector.Matches(labels) {
		return false, nil
	}

	return true, nil
}

func (s *Scanner) sendAdmissionReviewToPolicyServer(ctx context.Context, url *url.URL, admissionRequest *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the admission request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to build the policy server request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to policy server failed: %w ", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d body: %s", res.StatusCode, body)
	}

	admissionReview := admissionv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}

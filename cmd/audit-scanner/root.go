package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/k8s"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/policies"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/report"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/scanner"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/scheme"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultKubewardenNamespace = "kubewarden"
	defaultParallelResources   = 100
	defaultParallelPolicies    = 5
	defaultParallelNamespaces  = 1
	defaultPageSize            = 100
)

//nolint:gocognit,funlen // This function is the CLI entrypoint and it's expected to be long.
func NewRootCommand() *cobra.Command {
	var (
		level        string   // log level.
		outputScan   bool     // print result of scan as JSON to stdout.
		skippedNs    []string // list of namespaces to be skipped from scan.
		insecureSSL  bool     // skip SSL cert validation when connecting to PolicyServers endpoints.
		disableStore bool     // disable storing the results in the k8s cluster.
	)

	// rootCmd represents the base command when called without any subcommands.
	rootCmd := &cobra.Command{
		Use:   "audit-scanner",
		Short: "Reports evaluation of existing Kubernetes resources with your already deployed Kubewarden policies",
		Long: `Scans resources in your kubernetes cluster with your already deployed Kubewarden policies.
Each namespace will have a PolicyReport with the outcome of the scan for resources within this namespace.
There will be a ClusterPolicyReport with results for cluster-wide resources.`,

		RunE: func(cmd *cobra.Command, _ []string) error {
			logLevel, err := ParseLogLevel(level)
			if err != nil {
				return err
			}
			logger := slog.New(NewHandler(os.Stdout, os.Stderr, logLevel))

			namespace, err := cmd.Flags().GetString("namespace")
			if err != nil {
				return fmt.Errorf("failed to get namespace flag %w", err)
			}
			kubewardenNamespace, err := cmd.Flags().GetString("kubewarden-namespace")
			if err != nil {
				return fmt.Errorf("failed to get kubewarden-namespace flag: %w", err)
			}
			clusterWide, err := cmd.Flags().GetBool("cluster")
			if err != nil {
				return fmt.Errorf("failed to get cluster flag: %w", err)
			}
			policyServerURL, err := cmd.Flags().GetString("policy-server-url")
			if err != nil {
				return fmt.Errorf("failed to get policy-server-url flag: %w", err)
			}
			caFile, err := cmd.Flags().GetString("extra-ca")
			if err != nil {
				return fmt.Errorf("failed to get extra-ca flag: %w", err)
			}
			clientCertFile, err := cmd.Flags().GetString("client-cert")
			if err != nil {
				return fmt.Errorf("failed to get client-cert flag: %w", err)
			}
			clientKeyFile, err := cmd.Flags().GetString("client-key")
			if err != nil {
				return fmt.Errorf("failed to get client-key flag: %w", err)
			}
			parallelNamespacesAudits, err := cmd.Flags().GetInt("parallel-namespaces")
			if err != nil {
				return fmt.Errorf("failed to get parallel-namespaces flag: %w", err)
			}
			parallelResourcesAudits, err := cmd.Flags().GetInt("parallel-resources")
			if err != nil {
				return fmt.Errorf("failed to get parallel-resources flag: %w", err)
			}
			parallelPoliciesAudit, err := cmd.Flags().GetInt("parallel-policies")
			if err != nil {
				return fmt.Errorf("failed to get parallel-policies flag: %w", err)
			}
			pageSize, err := cmd.Flags().GetInt("page-size")
			if err != nil {
				return fmt.Errorf("failed to get page-size flag: %w", err)
			}
			reportKindStr, err := cmd.Flags().GetString("report-kind")
			if err != nil {
				return fmt.Errorf("failed to get report-kind flag: %w", err)
			}

			var reportKind report.CrdKind
			switch reportKindStr {
			case report.OpenReportsKind:
				reportKind = report.ReportKindOpenReport
			case report.PolicyReportKind:
				reportKind = report.ReportKindPolicyReport
			default:
				return fmt.Errorf("invalid report-kind '%s': supported values are '%s' and '%s'", reportKindStr, report.OpenReportsKind, report.PolicyReportKind)
			}

			config := ctrl.GetConfigOrDie()
			dynamicClient := dynamic.NewForConfigOrDie(config)
			clientset := kubernetes.NewForConfigOrDie(config)

			auditScheme, err := scheme.NewScheme()
			if err != nil {
				return fmt.Errorf("failed to create scheme: %w", err)
			}
			client, err := client.New(config, client.Options{Scheme: auditScheme})
			if err != nil {
				return fmt.Errorf("failed to create kubernetes client: %w", err)
			}
			policiesClient := policies.NewClient(client, kubewardenNamespace, policyServerURL, logger)

			k8sClient := k8s.NewClient(dynamicClient, clientset, kubewardenNamespace, skippedNs, int64(pageSize), logger)
			reportStore := report.NewReportStoreOfKind(reportKind, client, logger)

			if reportKind == report.ReportKindOpenReport {
				if disableStore {
					logger.Debug("store disabled, skipping deletion of legacy wgpolicyk8s.io PolicyReports")
				} else if err = report.DeleteAllLegacyPolicyReports(context.Background(), client, logger); err != nil {
					logger.Warn("Failed to delete legacy wgpolicyk8s.io PolicyReports, continuing", "error", err)
				}
			}

			scannerConfig := scanner.Config{
				PoliciesClient: policiesClient,
				K8sClient:      k8sClient,
				ReportStore:    reportStore,
				TLS: scanner.TLSConfig{
					Insecure:       insecureSSL,
					CAFile:         caFile,
					ClientCertFile: clientCertFile,
					ClientKeyFile:  clientKeyFile,
				},
				Parallelization: scanner.ParallelizationConfig{
					ParallelNamespacesAudits: parallelNamespacesAudits,
					ParallelResourcesAudits:  parallelResourcesAudits,
					PoliciesAudits:           parallelPoliciesAudit,
				},
				OutputScan:   outputScan,
				DisableStore: disableStore,
				Logger:       logger.With("component", "scanner"),
				ReportKind:   reportKind,
			}

			scanner, err := scanner.NewScanner(scannerConfig)
			if err != nil {
				return fmt.Errorf("failed to create scanner: %w", err)
			}
			return startScanner(namespace, clusterWide, scanner)
		},
	}

	// make sure we always get json formatted errors, even for flag errors
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
	rootCmd.Flags().BoolP("cluster", "c", false, "scan cluster wide resources")
	rootCmd.Flags().StringP("kubewarden-namespace", "k", defaultKubewardenNamespace, "namespace where the Kubewarden components (e.g. PolicyServer) are installed (required)")
	rootCmd.Flags().StringP("policy-server-url", "u", "", "URI to the PolicyServers the Audit Scanner will query. Example: https://localhost:3000. Useful for out-of-cluster debugging")
	rootCmd.Flags().StringVarP(&level, "loglevel", "l", LevelInfoString, fmt.Sprintf("level of the logs. Supported values are: %v", SupportedLogLevels()))
	rootCmd.Flags().BoolVarP(&outputScan, "output-scan", "o", false, "print result of scan in JSON to stdout")
	rootCmd.Flags().StringSliceVarP(&skippedNs, "ignore-namespaces", "i", nil, "comma separated list of namespace names to be skipped from scan. This flag can be repeated")
	rootCmd.Flags().BoolVar(&insecureSSL, "insecure-ssl", false, "skip SSL cert validation when connecting to PolicyServers endpoints. Useful for development")
	rootCmd.Flags().StringP("extra-ca", "f", "", "File path to CA cert in PEM format of PolicyServer endpoints")
	rootCmd.Flags().StringP("client-cert", "", "", "File path to client cert in PEM format used for mTLS communication with the PolicyServer endpoints")
	rootCmd.Flags().StringP("client-key", "", "", "File path to client key in PEM format used for mTLS communication with the PolicyServer endpoints")
	rootCmd.MarkFlagsRequiredTogether("client-cert", "client-key")
	rootCmd.MarkFlagsMutuallyExclusive("cluster", "namespace")
	rootCmd.Flags().BoolVar(&disableStore, "disable-store", false, "do not create, update or delete (Cluster)Reports in the cluster; scan results are only computed in memory (use with --output-scan)")
	rootCmd.Flags().IntP("parallel-namespaces", "", defaultParallelNamespaces, "number of Namespaces to scan in parallel")
	rootCmd.Flags().IntP("parallel-resources", "", defaultParallelResources, "number of resources to scan in parallel")
	rootCmd.Flags().IntP("parallel-policies", "", defaultParallelPolicies, "number of policies to evaluate for a given resource in parallel")
	rootCmd.Flags().IntP("page-size", "", defaultPageSize, "number of resources to fetch from the Kubernetes API server when paginating")
	rootCmd.Flags().StringP("report-kind", "", report.PolicyReportKind, "Report resource kind to be used. Supported values are 'openreport' and 'policyreport'")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(rootCmd *cobra.Command) {
	if err := rootCmd.Execute(); err != nil {
		logger := slog.New(NewHandler(os.Stdout, os.Stderr, slog.LevelError))
		logger.Error("audit scanner failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

//nolint:wrapcheck // this function calls internal package which already wrap the errors with context
func startScanner(namespace string, clusterWide bool, scanner *scanner.Scanner) error {
	runUID := uuid.New().String()
	ctx := context.Background()
	if clusterWide {
		// only scan clusterwide
		return scanner.ScanClusterWideResources(ctx, runUID)
	}
	if namespace != "" {
		// only scan namespace
		return scanner.ScanNamespace(ctx, namespace, runUID)
	}

	// default mode
	clusterErr := scanner.ScanClusterWideResources(ctx, runUID)
	nsErr := scanner.ScanAllNamespaces(ctx, runUID)
	return errors.Join(clusterErr, nsErr)
}

// Copyright 2025 The Kube-burner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workloads

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloud-bulldozer/go-commons/v2/virtctl"
	"github.com/kube-burner/kube-burner/v2/pkg/workloads"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"
)

const (
	mssqlNamespace        = "windows-mssql"
	mssqlJobLabel         = "create-windows-vms"
	mssqlSSHMaxRetries    = 200
	mssqlSSHPollInterval  = 5 * time.Second
	mssqlConcurrencyLimit = 10
	mssqlSCPRetries       = 3
	mssqlHammerDBDir      = `C:/tools/hammerdb-4.12`
	mssqlScriptsDir       = "config/windows-mssql/scripts"
)

var mssqlScriptNames = []string{
	"run_prepare_hammerdb.ps1",
	"run_hammerdb_benchmark.ps1",
	"01_provision-data-disk.ps1",
	"02_create_db.sql",
	"03_buildschema_mssql.tcl",
	"04_traceflags.sql",
	"05_hammerdb-auto-runs.ps1",
	"06_parse_results.ps1",
}

// mssqlThreadResult holds the TPC-C result for one worker-count run on one VM.
type mssqlThreadResult struct {
	VMName        string  `json:"vm_name"`
	Node          string  `json:"node"`
	CurrentWorker int     `json:"current_worker"`
	TPM           float64 `json:"tpm"`
	NOPM          float64 `json:"nopm"`
	DBWarehouses  int     `json:"db_warehouses"`
}

type mssqlRunConfig struct {
	sshKey       string
	sshUser      string
	dbWorkers    int
	dbWarehouses int
	ocpConfig    fs.ReadFileFS
}

// NewWindowsMSSQL returns the windows-mssql workload command.
func NewWindowsMSSQL(wh *workloads.WorkloadHelper, ocpConfig fs.ReadFileFS) *cobra.Command {
	var windowsImageURL, storageClassName, volumeAccessMode, vmMemory, storageSize, dataDiskSize string
	var vmsPerNode, vmCPU, dbWarehouses, dbWorkers int
	var sshKey, sshUser string
	var vmiRunningThreshold time.Duration
	var metricsProfiles []string
	var rc int
	cmd := &cobra.Command{
		Use:          "windows-mssql",
		Short:        "Runs windows-mssql HammerDB TPC-C workload on Windows VMs",
		SilenceUsage: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			if windowsImageURL == "" {
				log.Fatal("--windows-image-url is required")
			}
			if _, ok := accessModeTranslator[volumeAccessMode]; !ok {
				log.Fatalf("Unsupported access mode - %s", volumeAccessMode)
			}
			if !virtctl.IsInstalled() {
				log.Fatal("Failed to run virtctl. Check that it is installed, in PATH and working")
			}
			storageClassName, _ = getStorageAndSnapshotClasses(storageClassName, false, false)

			// Auto-generate or reuse SSH key pair if not provided
			if sshKey == "" {
				defaultKeyPath, err := defaultSSHKeyPath()
				if err != nil {
					log.Fatalf("Failed to determine SSH key path: %v", err)
				}
				if _, err := os.Stat(defaultKeyPath); os.IsNotExist(err) {
					log.Infof("Generating persistent SSH key pair at %s", defaultKeyPath)
					privKeyPath, pubKey, err := generateSSHKeyPair(defaultKeyPath)
					if err != nil {
						log.Fatalf("Failed to generate SSH key pair: %v", err)
					}
					sshKey = privKeyPath
					AdditionalVars["sshPublicKey"] = pubKey
					log.Infof("SSH key generated. Add this public key to your Windows image's authorized_keys ONCE:")
					log.Infof("  %s", pubKey)
					log.Infof("Public key also saved to: %s.pub", defaultKeyPath)
				} else {
					log.Infof("Reusing existing SSH key: %s", defaultKeyPath)
					sshKey = defaultKeyPath
					pubKey, err := derivePublicKey(defaultKeyPath)
					if err != nil {
						log.Fatalf("Failed to read public key from %s: %v", defaultKeyPath, err)
					}
					AdditionalVars["sshPublicKey"] = pubKey
				}
			} else {
				if _, err := os.Stat(sshKey); err != nil {
					log.Fatalf("SSH key not found: %s", sshKey)
				}
				pubKey, err := derivePublicKey(sshKey)
				if err != nil {
					log.Fatalf("Failed to read public key from %s: %v", sshKey, err)
				}
				AdditionalVars["sshPublicKey"] = pubKey
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			totalVMs := clusterMetadata.WorkerNodesCount * vmsPerNode

			AdditionalVars["JOB_ITERATIONS"] = totalVMs
			AdditionalVars["VMI_RUNNING_THRESHOLD"] = vmiRunningThreshold
			AdditionalVars["windowsImageURL"] = windowsImageURL
			AdditionalVars["storageClassName"] = storageClassName
			AdditionalVars["accessMode"] = accessModeTranslator[volumeAccessMode]
			AdditionalVars["vmMemory"] = vmMemory
			AdditionalVars["vmCPU"] = vmCPU
			AdditionalVars["storageSize"] = storageSize
			AdditionalVars["dataDiskSize"] = dataDiskSize
			AdditionalVars["dbWarehouses"] = dbWarehouses
			AdditionalVars["dbWorkers"] = dbWorkers

			setMetrics(cmd, metricsProfiles)
			AddVirtMetadata(wh, "", "", "")
			rc = RunWorkload(cmd, wh, cmd.Name()+".yml")

			if rc == 0 {
				cfg := mssqlRunConfig{
					sshKey:       sshKey,
					sshUser:      sshUser,
					dbWorkers:    dbWorkers,
					dbWarehouses: dbWarehouses,
					ocpConfig:    ocpConfig,
				}
				threadResults := runMSSQLOnVMs(cmd.Context(), cfg)
				writeMSSQLResults(threadResults, wh)
			}
			cleanupMSSQLNamespace(cmd.Context())
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			os.Exit(rc)
		},
	}
	cmd.Flags().StringVar(&windowsImageURL, "windows-image-url", "", "HTTP URL to Windows QCOW2 disk image")
	cmd.Flags().IntVar(&vmsPerNode, "vms-per-node", 1, "Number of Windows VMs to create per worker node")
	cmd.Flags().StringVar(&storageClassName, "storage-class", "", "Storage class for DataVolumes (auto-detected if empty)")
	cmd.Flags().StringVar(&volumeAccessMode, "access-mode", "RWX", "PVC access mode: RO, RWO, RWX")
	cmd.Flags().StringVar(&vmMemory, "vm-memory", "16G", "Memory request and limit per VM")
	cmd.Flags().IntVar(&vmCPU, "vm-cpu", 2, "CPU sockets per VM")
	cmd.Flags().StringVar(&storageSize, "storage-size", "76Gi", "Root disk storage size")
	cmd.Flags().StringVar(&dataDiskSize, "data-disk-size", "76Gi", "MSSQL data disk size")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "Path to SSH private key for Windows VM access (auto-generated if not provided)")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "Administrator", "Windows SSH username")
	cmd.Flags().IntVar(&dbWarehouses, "db-warehouses", 2, "HammerDB TPC-C number of warehouses")
	cmd.Flags().IntVar(&dbWorkers, "db-workers", 2, "HammerDB TPC-C number of worker threads")
	cmd.Flags().DurationVar(&vmiRunningThreshold, "vmi-ready-threshold", 0, "VMI ready timeout threshold")
	cmd.Flags().StringSliceVar(&metricsProfiles, "metrics-profile", []string{"metrics.yml"}, "Comma separated list of metrics profiles to use")
	return cmd
}

// defaultSSHKeyPath returns ~/.ssh/windows-mssql-id_rsa.
func defaultSSHKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "windows-mssql-id_rsa"), nil
}

// generateSSHKeyPair creates a 4096-bit RSA key pair, writes the private key to privKeyPath
// (and the public key to privKeyPath+".pub"), and returns (privateKeyPath, authorizedKeysLine, error).
func generateSSHKeyPair(privKeyPath string) (string, string, error) {
	if err := os.MkdirAll(filepath.Dir(privKeyPath), 0700); err != nil {
		return "", "", fmt.Errorf("create .ssh dir: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privKeyPath, privPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write private key: %w", err)
	}

	// Derive authorized_keys format public key
	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		os.Remove(privKeyPath)
		return "", "", fmt.Errorf("derive public key: %w", err)
	}
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))

	// Also save .pub file for convenience
	pubPath := privKeyPath + ".pub"
	_ = os.WriteFile(pubPath, []byte(authorizedKey+"\n"), 0644)

	return privKeyPath, authorizedKey, nil
}

// derivePublicKey reads the private key at path and returns the authorized_keys line.
func derivePublicKey(privKeyPath string) (string, error) {
	data, err := os.ReadFile(privKeyPath)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", err
	}
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return authorizedKey, nil
}

func runMSSQLOnVMs(ctx context.Context, cfg mssqlRunConfig) []mssqlThreadResult {
	k8sConnector := getK8SConnector()
	vmGVR := schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}

	vmList, err := k8sConnector.DynamicClient().Resource(vmGVR).Namespace(mssqlNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("kube-burner.io/job=%s", mssqlJobLabel),
	})
	if err != nil {
		log.Errorf("Failed to list VMs: %v", err)
		return nil
	}

	vmNames := make([]string, 0, len(vmList.Items))
	for _, vm := range vmList.Items {
		vmNames = append(vmNames, vm.GetName())
	}

	// Extract embedded scripts to a shared temp dir
	tmpDir, err := os.MkdirTemp("", "windows-mssql-scripts-*")
	if err != nil {
		log.Errorf("Failed to create temp dir for scripts: %v", err)
		return nil
	}
	defer os.RemoveAll(tmpDir)

	if err := extractScripts(cfg.ocpConfig, tmpDir, cfg.dbWarehouses, cfg.dbWorkers); err != nil {
		log.Errorf("Failed to extract scripts: %v", err)
		return nil
	}

	// Wait for all VMs to reach Stopped (DV clones done)
	log.Infof("Waiting for %d VMs to reach Stopped status...", len(vmNames))
	var stopWg sync.WaitGroup
	for _, name := range vmNames {
		stopWg.Add(1)
		go func(n string) {
			defer stopWg.Done()
			waitForVMStatus(ctx, n, mssqlNamespace, "Stopped")
		}(name)
	}
	stopWg.Wait()
	log.Infof("All VMs Stopped. Starting %d VMs (concurrency: %d)", len(vmNames), mssqlConcurrencyLimit)

	// Run benchmark on all VMs in parallel — collect per-thread results
	var allResults []mssqlThreadResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, mssqlConcurrencyLimit)

	for _, vmName := range vmNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results := runBenchmarkOnVM(ctx, name, tmpDir, cfg)
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(vmName)
	}
	wg.Wait()

	log.Infof("MSSQL benchmark complete: %d thread results across %d VMs", len(allResults), len(vmNames))
	return allResults
}

func runBenchmarkOnVM(ctx context.Context, vmName, scriptsDir string, cfg mssqlRunConfig) []mssqlThreadResult {
	empty := []mssqlThreadResult{{VMName: vmName, DBWarehouses: cfg.dbWarehouses}}

	log.Infof("Starting VM %s", vmName)
	if err := exec.CommandContext(ctx, "virtctl", "start", vmName, "-n", mssqlNamespace).Run(); err != nil {
		log.Warnf("Failed to start VM %s: %v", vmName, err)
		return empty
	}

	// Wait for Running
	waitForVMStatus(ctx, vmName, mssqlNamespace, "Running")

	// Wait for SSH with key auth
	log.Infof("Waiting for SSH on VM %s...", vmName)
	if !waitForSSH(ctx, vmName, cfg.sshKey, cfg.sshUser) {
		log.Warnf("SSH key auth never became ready on VM %s — cloudbase-init may not have executed runcmd (image needs sysprep)", vmName)
		return empty
	}

	// Verify SSH authorized key file was injected by cloudbase-init
	out, err := runSSHCommand(ctx, vmName, cfg.sshKey, cfg.sshUser,
		`powershell -Command "if (Test-Path C:\ProgramData\ssh\administrators_authorized_keys) { echo key_ok }"`)
	if err != nil || !strings.Contains(out, "key_ok") {
		log.Warnf("SSH key file not found on VM %s — cloudbase-init runcmd may not have executed (image needs sysprep)", vmName)
	}

	// SCP scripts
	log.Infof("Copying scripts to VM %s...", vmName)
	if err := scpScriptsToVM(ctx, vmName, cfg.sshKey, cfg.sshUser, scriptsDir); err != nil {
		log.Warnf("Failed to SCP scripts to VM %s: %v", vmName, err)
		return empty
	}

	// Run prepare phase
	log.Infof("Running prepare phase on VM %s...", vmName)
	if err := runPSScript(ctx, vmName, cfg.sshKey, cfg.sshUser, "run_prepare_hammerdb.ps1"); err != nil {
		log.Warnf("Prepare phase failed on VM %s: %v", vmName, err)
		return empty
	}

	// Run benchmark phase
	log.Infof("Running HammerDB benchmark on VM %s...", vmName)
	if err := runPSScript(ctx, vmName, cfg.sshKey, cfg.sshUser, "run_hammerdb_benchmark.ps1"); err != nil {
		log.Warnf("Benchmark phase failed on VM %s: %v", vmName, err)
		return empty
	}

	// Collect per-thread results
	return collectMSSQLResults(ctx, vmName, cfg.sshKey, cfg.sshUser, cfg.dbWarehouses)
}

func waitForVMStatus(ctx context.Context, vmName, namespace, status string) {
	for {
		if ctx.Err() != nil {
			return
		}
		output, _ := exec.CommandContext(ctx, "kubectl", "get", "vm", vmName, "-n", namespace,
			"-o", "jsonpath={.status.printableStatus}").Output()
		if strings.TrimSpace(string(output)) == status {
			return
		}
		time.Sleep(mssqlSSHPollInterval)
	}
}

func runSSHCommand(ctx context.Context, vmName, sshKey, sshUser, command string) (string, error) {
	args := []string{
		"ssh",
		"--username=" + sshUser,
		"--identity-file=" + sshKey,
		"--known-hosts=",
		"-t", "-oStrictHostKeyChecking=no",
		"-t", "-oUserKnownHostsFile=/dev/null",
		"-t", "-oBatchMode=yes",
		"-n", mssqlNamespace,
		fmt.Sprintf("--command=%s", command),
		fmt.Sprintf("vmi/%s", vmName),
	}
	out, err := exec.CommandContext(ctx, "virtctl", args...).CombinedOutput()
	return string(out), err
}

func waitForSSH(ctx context.Context, vmName, sshKey, sshUser string) bool {
	for attempt := 1; attempt <= mssqlSSHMaxRetries; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		_, err := runSSHCommand(ctx, vmName, sshKey, sshUser, "echo ok")
		if err == nil {
			log.Infof("SSH ready on VM %s (attempt %d)", vmName, attempt)
			return true
		}
		time.Sleep(mssqlSSHPollInterval)
	}
	return false
}

func scpToVM(ctx context.Context, vmName, sshKey, sshUser, localPath, remotePath string) error {
	args := []string{
		"scp",
		"--identity-file=" + sshKey,
		"--known-hosts=",
		"-t", "-oStrictHostKeyChecking=no",
		"-t", "-oUserKnownHostsFile=/dev/null",
		"-n", mssqlNamespace,
		localPath,
		fmt.Sprintf("%s@vmi/%s:%s", sshUser, vmName, remotePath),
	}
	out, err := exec.CommandContext(ctx, "virtctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp failed: %v — %s", err, string(out))
	}
	return nil
}

func scpToVMWithVerify(ctx context.Context, vmName, sshKey, sshUser, localPath, remotePath string) error {
	script := filepath.Base(localPath)
	for attempt := 1; attempt <= mssqlSCPRetries; attempt++ {
		if err := scpToVM(ctx, vmName, sshKey, sshUser, localPath, remotePath); err != nil {
			log.Warnf("SCP %s to VM %s failed (attempt %d/%d): %v", script, vmName, attempt, mssqlSCPRetries, err)
			time.Sleep(5 * time.Second)
			continue
		}
		verifyCmd := fmt.Sprintf(`powershell -Command "if (Test-Path '%s') { echo exists }"`, remotePath)
		out, err := runSSHCommand(ctx, vmName, sshKey, sshUser, verifyCmd)
		if err == nil && strings.Contains(out, "exists") {
			log.Infof("Copied and verified %s on VM %s", script, vmName)
			return nil
		}
		log.Warnf("SCP verify failed for %s on VM %s (attempt %d/%d)", script, vmName, attempt, mssqlSCPRetries)
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("failed to SCP %s to VM %s after %d attempts", script, vmName, mssqlSCPRetries)
}

func scpScriptsToVM(ctx context.Context, vmName, sshKey, sshUser, localDir string) error {
	for _, script := range mssqlScriptNames {
		localPath := filepath.Join(localDir, script)
		remotePath := fmt.Sprintf("%s/%s", mssqlHammerDBDir, script)

		if script == "03_buildschema_mssql.tcl" {
			remotePath = fmt.Sprintf("%s/scripts/tcl/mssqls/tprocc/%s", mssqlHammerDBDir, script)
		}

		if err := scpToVMWithVerify(ctx, vmName, sshKey, sshUser, localPath, remotePath); err != nil {
			return err
		}
	}
	return nil
}

func scpFromVM(ctx context.Context, vmName, sshKey, sshUser, remotePath, localPath string) error {
	args := []string{
		"scp",
		"--identity-file=" + sshKey,
		"--known-hosts=",
		"-t", "-oStrictHostKeyChecking=no",
		"-t", "-oUserKnownHostsFile=/dev/null",
		"-n", mssqlNamespace,
		fmt.Sprintf("%s@vmi/%s:%s", sshUser, vmName, remotePath),
		localPath,
	}
	out, err := exec.CommandContext(ctx, "virtctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp from vm failed: %v — %s", err, string(out))
	}
	return nil
}

func runPSScript(ctx context.Context, vmName, sshKey, sshUser, script string) error {
	psCmd := fmt.Sprintf("powershell -NoProfile -ExecutionPolicy Bypass -File %s/%s", mssqlHammerDBDir, script)
	out, err := runSSHCommand(ctx, vmName, sshKey, sshUser, psCmd)
	if out != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				log.Infof("[%s] %s: %s", vmName, script, line)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("script %s failed: %v", script, err)
	}
	log.Infof("Script %s completed on VM %s", script, vmName)
	return nil
}

func collectMSSQLResults(ctx context.Context, vmName, sshKey, sshUser string, dbWarehouses int) []mssqlThreadResult {
	node := getMSSQLVMINode(vmName)
	empty := []mssqlThreadResult{{VMName: vmName, Node: node, DBWarehouses: dbWarehouses}}

	resultsDir := "./windows-mssql-results"
	_ = os.MkdirAll(resultsDir, 0755)

	// SCP VM logs back to local
	for _, logName := range []string{"run_prepare_hammerdb.log", "run_hammerdb_benchmark.log"} {
		localLog := filepath.Join(resultsDir, fmt.Sprintf("%s_%s", vmName, logName))
		remoteLog := fmt.Sprintf("%s/%s", mssqlHammerDBDir, logName)
		if err := scpFromVM(ctx, vmName, sshKey, sshUser, remoteLog, localLog); err != nil {
			log.Warnf("Failed to SCP %s from VM %s: %v", logName, vmName, err)
		} else {
			log.Infof("Copied %s from VM %s to %s", logName, vmName, localLog)
		}
	}

	// Wait for hammerdb_result.json to exist on the VM before copying
	localResult := filepath.Join(resultsDir, fmt.Sprintf("hammerdb_result_%s.json", vmName))
	remotePath := fmt.Sprintf("%s/results/hammerdb_result.json", mssqlHammerDBDir)
	checkCmd := fmt.Sprintf(`powershell -Command "if (Test-Path '%s') { echo found }"`, remotePath)

	found := false
	for elapsed := 0; elapsed < 3600; elapsed += 30 {
		if ctx.Err() != nil {
			return empty
		}
		out, err := runSSHCommand(ctx, vmName, sshKey, sshUser, checkCmd)
		if err == nil && strings.Contains(out, "found") {
			found = true
			break
		}
		log.Infof("Waiting for hammerdb_result.json on VM %s... (%ds)", vmName, elapsed)
		time.Sleep(30 * time.Second)
	}
	if !found {
		log.Warnf("hammerdb_result.json not found on VM %s within timeout", vmName)
		return empty
	}

	if err := scpFromVM(ctx, vmName, sshKey, sshUser, remotePath, localResult); err != nil {
		log.Warnf("Failed to SCP results from VM %s: %v", vmName, err)
		return empty
	}
	if _, err := os.Stat(localResult); err != nil {
		log.Warnf("hammerdb_result.json not found locally at %s", localResult)
		return empty
	}
	log.Infof("Copied hammerdb_result.json from VM %s to %s", vmName, localResult)

	data, err := os.ReadFile(localResult)
	if err != nil {
		log.Warnf("Failed to read results file for VM %s: %v", vmName, err)
		return empty
	}

	// hammerdb_result.json is an array of {current_worker, tpm}
	var entries []struct {
		CurrentWorker int     `json:"current_worker"`
		TPM           float64 `json:"tpm"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Warnf("Failed to parse results for VM %s: %v", vmName, err)
		return empty
	}

	// Build one result per thread count
	results := make([]mssqlThreadResult, 0, len(entries))
	for _, e := range entries {
		nopm := e.TPM * 0.45
		log.Infof("VM %s | workers=%d TPM=%.0f NOPM=%.0f", vmName, e.CurrentWorker, e.TPM, nopm)
		results = append(results, mssqlThreadResult{
			VMName:        vmName,
			Node:          node,
			CurrentWorker: e.CurrentWorker,
			TPM:           e.TPM,
			NOPM:          nopm,
			DBWarehouses:  dbWarehouses,
		})
	}
	return results
}

func getMSSQLVMINode(vmName string) string {
	output, err := exec.Command("kubectl", "get", "vmi", vmName, "-n", mssqlNamespace,
		"-o", "jsonpath={.status.nodeName}").Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func extractScripts(ocpConfig fs.ReadFileFS, destDir string, dbWarehouses, dbWorkers int) error {
	replacer := strings.NewReplacer(
		"DB_WAREHOUSES", fmt.Sprintf("%d", dbWarehouses),
		"DB_WORKERS", fmt.Sprintf("%d", dbWorkers),
	)
	for _, script := range mssqlScriptNames {
		data, err := ocpConfig.ReadFile(filepath.Join(mssqlScriptsDir, script))
		if err != nil {
			return fmt.Errorf("failed to read embedded script %s: %w", script, err)
		}
		content := replacer.Replace(string(data))
		if err := os.WriteFile(filepath.Join(destDir, script), []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write script %s: %w", script, err)
		}
	}
	return nil
}

func writeMSSQLResults(results []mssqlThreadResult, wh *workloads.WorkloadHelper) {
	if len(results) == 0 {
		log.Warn("No MSSQL results to write")
		return
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	docs := make([]map[string]any, len(results))
	for i, r := range results {
		docs[i] = map[string]any{
			"vm_name":        r.VMName,
			"node":           r.Node,
			"current_worker": r.CurrentWorker,
			"tpm":            r.TPM,
			"nopm":           r.NOPM,
			"db_warehouses":  r.DBWarehouses,
			"uuid":           AdditionalVars["UUID"],
			"metricName":     "winMSSQLResult",
			"jobName":        mssqlJobLabel,
			"timestamp":      ts,
			"metadata":       wh.MetricsMetadata,
		}
	}

	outData, err := json.MarshalIndent(docs, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshal MSSQL results: %v", err)
		return
	}

	resultsDir := "./windows-mssql-results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Errorf("Failed to create results dir: %v", err)
		return
	}
	outPath := filepath.Join(resultsDir, "winMSSQLResult-create-windows-vms.json")
	if err := os.WriteFile(outPath, outData, 0644); err != nil {
		log.Errorf("Failed to write MSSQL results to %s: %v", outPath, err)
		return
	}
	log.Infof("MSSQL results written to %s (%d VMs)", outPath, len(results))
}

func cleanupMSSQLNamespace(ctx context.Context) {
	k8sConnector := getK8SConnector()
	log.Infof("Cleaning up namespace %s", mssqlNamespace)
	err := k8sConnector.ClientSet().CoreV1().Namespaces().Delete(ctx, mssqlNamespace, metav1.DeleteOptions{})
	if err != nil {
		log.Warnf("Failed to delete namespace %s: %v", mssqlNamespace, err)
	} else {
		log.Infof("Namespace %s deleted", mssqlNamespace)
	}
}

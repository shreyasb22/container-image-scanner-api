package scanner

import (
	"os"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/trivy"
)

var cacheDir string = os.Getenv("HOME") + "/.cache"
var reportsDir string = os.Getenv("HOME") + "/.reports"

type MyRegistryAuth struct {
	trivy.NoAuth
}

func initDir() {
	os.MkdirAll(cacheDir, os.ModePerm)
	os.MkdirAll(reportsDir, os.ModePerm)
}

func RunTrivyScan(imageRef string) ([]trivy.Vulnerability, error) {
	initDir()

	auth := trivy.NoAuth{}

	w := trivy.NewWrapper(etc.Trivy{CacheDir: cacheDir,
		ReportsDir:     reportsDir,
		Severity:       "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		VulnType:       "os,library",
		SecurityChecks: "vuln",
		Timeout:        time.Minute * 5}, ext.DefaultAmbassador)

	var image trivy.ImageRef = trivy.ImageRef{
		Name:     imageRef,
		Auth:     auth,
		Insecure: false,
	}

	vulnerabilities, err := w.Scan(image)
	if err != nil {
		return vulnerabilities, err
	}

	return vulnerabilities, nil
}

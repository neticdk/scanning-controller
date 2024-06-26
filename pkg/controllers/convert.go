package controllers

import (
	"sort"
	"strings"

	trivyDBTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ty "github.com/aquasecurity/trivy/pkg/types"
	"github.com/openclarity/kubeclarity/shared/pkg/scanner"
	utilsVul "github.com/openclarity/kubeclarity/shared/pkg/utils/vulnerability"
)

// convertTrivyReport based on https://github.com/openclarity/kubeclarity/blob/main/shared/pkg/scanner/trivy/scanner.go#L285
func convertTrivyReport(report *ty.Report) ([]*scanner.MergedVulnerability, error) {
	matches := []*scanner.MergedVulnerability{}
	for _, result := range report.Results {
		for _, vul := range result.Vulnerabilities {
			typ := ""
			purl := ""
			if vul.PkgIdentifier.PURL != nil {
				typ = vul.PkgIdentifier.PURL.Type
				purl = vul.PkgIdentifier.PURL.String()
			}

			cvsses := getCVSSesFromVul(vul.CVSS)

			fix := scanner.Fix{}
			if vul.FixedVersion != "" {
				fix.Versions = []string{
					vul.FixedVersion,
				}
			}

			distro := scanner.Distro{}
			if report.Metadata.OS != nil {
				distro.Name = string(report.Metadata.OS.Family)
				distro.Version = report.Metadata.OS.Name
			}

			links := make([]string, 0, len(vul.Vulnerability.References))
			links = append(links, vul.Vulnerability.References...)
			kbVul := scanner.Vulnerability{
				ID:          vul.VulnerabilityID,
				Description: vul.Description,
				Links:       links,
				Distro:      distro,
				CVSS:        cvsses,
				Fix:         fix,
				Severity:    strings.ToUpper(vul.Severity),
				Package: scanner.Package{
					Name:     vul.PkgName,
					Version:  vul.InstalledVersion,
					PURL:     purl,
					Type:     typ,
					Language: "",
					Licenses: nil,
					CPEs:     nil,
				},
				LayerID: vul.Layer.Digest,
				Path:    vul.PkgPath,
			}

			matches = append(matches, &scanner.MergedVulnerability{
				Vulnerability: kbVul,
			})
		}
	}
	return matches, nil
}

func getCVSSesFromVul(vCvss trivyDBTypes.VendorCVSS) []scanner.CVSS {
	cvsses := []scanner.CVSS{}
	v2Collected := false
	v3Collected := false

	vendors := make([]string, 0, len(vCvss))
	for v := range vCvss {
		vendors = append(vendors, string(v))
	}
	sort.Strings(vendors)

	for _, vendor := range vendors {
		cvss := vCvss[trivyDBTypes.SourceID(vendor)]
		if cvss.V3Vector != "" && !v3Collected {
			exploit, impact := utilsVul.ExploitScoreAndImpactScoreFromV3Vector(cvss.V3Vector)

			cvsses = append(cvsses, scanner.CVSS{
				Version: utilsVul.GetCVSSV3VersionFromVector(cvss.V3Vector),
				Vector:  cvss.V3Vector,
				Metrics: scanner.CvssMetrics{
					BaseScore:           cvss.V3Score,
					ExploitabilityScore: &exploit,
					ImpactScore:         &impact,
				},
			})
			v3Collected = true
		}
		if cvss.V2Vector != "" && !v2Collected {
			exploit, impact := utilsVul.ExploitScoreAndImpactScoreFromV2Vector(cvss.V2Vector)

			cvsses = append(cvsses, scanner.CVSS{
				Version: "2.0",
				Vector:  cvss.V2Vector,
				Metrics: scanner.CvssMetrics{
					BaseScore:           cvss.V2Score,
					ExploitabilityScore: &exploit,
					ImpactScore:         &impact,
				},
			})
			v2Collected = true
		}
	}
	return cvsses
}

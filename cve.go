package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
)

type CVEDescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CVEDescription struct {
	Description []*CVEDescriptionData `json:"description_data"`
}

type CVE struct {
	Description  CVEDescription `json:"description"`
	data_type    string
	data_format  string
	data_version string
	meta_data    string
	problem_type string
	references   string
}

type CVENodes struct {
	CVEOperator string         `json:"operator,omitempty"`
	CVENegates  string         `json:"negates,omitempty"`
	CPEMatch    []*CVECPEMatch `json:"cpe_match,omitempty"`
	CVEChildren []*CVENodes    `json:"children,omitempty"`
}

type CVECPEName struct {
	CPE23Uri         string `json:"cpe23Uri"`
	CPE22Uri         string `json:"cpe22Uri,omitempty"`
	LastModifiedDate string
}

type CVECPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	CPE23Uri              string `json:"cpe23Uri"`
	CPE22Uri              string `json:"cpe22Uri,omitempty"`
	VersionStartExcluding string
	VersionStartIncluding string
	VersionEndExcluding   string
	VersionEndIncluding   string
	CVECPEName            []*CVECPEName `json:"cpe_name,omitempty"`
}

type CVEItemConfiguration struct {
	CVEDataVersion string      `json:"CVE_data_version"`
	CVENodes       []*CVENodes `json:"nodes,omitempty"`
}

type CVEBaseMetricV2 struct {
}

type CVEBaseMetricV3 struct {
}

type CVEImpact struct {
	BaseMetricV3 CVEBaseMetricV3
	BaseMetricV2 CVEBaseMetricV2
}

type CVEItem struct {
	CVEInfo          CVE                  `json:"cve"`
	Configuration    CVEItemConfiguration `json:"configurations,omitempty"`
	Impact           CVEImpact            `json:"impact,omitempty"`
	PublishedDate    string               `json:"publishedDate,omitempty"`
	LastModifiedDate string               `json:"lastModifiedDate,omitempty"`
}

type CVEMain struct {
	CVEDataType    string
	CVEDataFormat  string
	CVEDataVersion string
	CVENumber      int
	CVETimestamp   string
	CVEItems       []*CVEItem `json:"CVE_Items"`
}

func main() {
	file, err := os.Open("nvdcve-1.1-modified.json")
	if err != nil {
		log.Fatal("Failed to open JSON file with CVEs")
	}

	var result CVEMain

	if err := json.NewDecoder(file).Decode(&result); err != nil {
		fmt.Printf("%s\n", err)
		log.Fatal("Failed to parse JSON file")
	}

	//fmt.Printf("%v", result.CVEItems)
	for i, item := range result.CVEItems {

		for _, node := range item.Configuration.CVENodes {
			for _, cpes := range node.CPEMatch {
				cpeLinuxKernel := "linux:linux_kernel"
				matched, _ := regexp.Match(cpeLinuxKernel, []byte(cpes.CPE23Uri))
				if matched == true {
					fmt.Printf("%v: %v\n", i, item.CVEInfo.Description.Description[0].Value)
				}
			}
		}
	}
}

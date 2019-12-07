package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

type CVEDescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CVEDescription struct {
	Description []*CVEDescriptionData `json:"description_data"`
}

type CVEMetaData struct {
	ID       string `json:"ID"`
	Assigner string
}

type CVE struct {
	Description  CVEDescription `json:"description"`
	data_type    string
	data_format  string
	data_version string
	MetaData     CVEMetaData `json:"CVE_data_meta"`
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

func cpeMatch(cpes *CVECPEMatch, cpePattern string) bool {
	matched, _ := regexp.Match(cpePattern, []byte(cpes.CPE23Uri))
	if matched == true && cpes.Vulnerable == true {
		return true
	}
	return false
}

func descMatch(description []*CVEDescriptionData, descPattern string) bool {
	for _, desc := range description {
		matched, _ := regexp.Match(descPattern, []byte(desc.Value))
		if matched == true {
			return true
		}
	}
	return false
}

//const cveJSONFeedURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"

const cveJSONFeedURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz"

func getJSONFeed(url string) (resp *http.Response, err error) {
	resp, err = http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Can't contact the URL for feeds %s", url)
	}
	return resp, nil
}

func main() {
	var result CVEMain

	uniquecves := make(map[string]bool)

	resp, err := getJSONFeed(cveJSONFeedURL)
	if err != nil {
		log.Fatal(err)
		return
	}

	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Printf("%s\n", err)
		log.Fatal("Failed to parse gzipped JSON file")
		resp.Body.Close()
	}

	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		fmt.Printf("%s\n", err)
		log.Fatal("Failed to parse JSON file")
		resp.Body.Close()
	}

	//fmt.Printf("%v", result.CVEItems)
	for _, item := range result.CVEItems {

		for _, node := range item.Configuration.CVENodes {
			for _, cpes := range node.CPEMatch {
				if cpeMatch(cpes, "linux:linux_kernel") &&
					uniquecves[item.CVEInfo.MetaData.ID] == false {
					fmt.Printf("%v: %v\n", item.CVEInfo.MetaData.ID,
						item.CVEInfo.Description.Description[0].Value)
					uniquecves[item.CVEInfo.MetaData.ID] = true
				}
				if descMatch(item.CVEInfo.Description.Description, "[lL]inux.*[kK]ernel") &&
					uniquecves[item.CVEInfo.MetaData.ID] == false {
					fmt.Printf("%v: %v\n", item.CVEInfo.MetaData.ID,
						item.CVEInfo.Description.Description[0].Value)
					uniquecves[item.CVEInfo.MetaData.ID] = true
				}
			}
		}
	}

	resp.Body.Close()
}

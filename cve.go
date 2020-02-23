package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
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
	Vulnerable            bool          `json:"vulnerable"`
	CPE23Uri              string        `json:"cpe23Uri"`
	CPE22Uri              string        `json:"cpe22Uri,omitempty"`
	VersionStartExcluding string        `json: versionStartExcluding`
	VersionStartIncluding string        `json: versionStartIncluding`
	VersionEndExcluding   string        `json: versionEndExcluding`
	VersionEndIncluding   string        `json: versionEndIncluding`
	CVECPEName            []*CVECPEName `json:"cpe_name,omitempty"`
}

type CVEItemConfiguration struct {
	CVEDataVersion string      `json:"CVE_data_version"`
	CVENodes       []*CVENodes `json:"nodes,omitempty"`
}

type CPECVSSV3 struct {
	version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type CVEBaseMetricV2 struct {
}

type CVEBaseMetricV3 struct {
	CVSSV3             CPECVSSV3 `json:"cvssV3"`
	ExploitabiltyScore float64   `json:"exploitabilityScore"`
	ImpactScore        float64   `json:"impactScore"`
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

var year = flag.String("year", "2020",
	"The year for which CVE's should be searched, for example 2020")

var cpe = flag.String("cpe", "linux:linux_kernel",
	"cpe to match against for example linux:linux_kernel")

var keyword = flag.String("keyword", "",
	"Regex of keywords to search, for example, [lL]inux or use empty "+
		"string \"\" to ignore keywords")

var version = flag.String("version", "", "version string like 4.14")

// This is harder to do, versions can be arbitrary strings
// we assume there is a sort order (comparable) defined
func versionMatch(cpe *CVECPEMatch, cpePattern string, version string) bool {

	//fmt.Printf("Matching pattern %v against %v\n", cpePattern, cpe.CPE23Uri)
	matched, _ := regexp.Match(cpePattern, []byte(cpe.CPE23Uri))

	if version == "" {
		//fmt.Printf("Version not specified, returing matched %v\n", matched)
		return matched
	}

	if matched == false {
		return false
	}

	if cpe.VersionStartIncluding != "" && version < cpe.VersionStartIncluding {
		//fmt.Printf("Failed match, version %v, Including %v\n", version, cpe.VersionStartIncluding)
		return false
	}
	if cpe.VersionStartExcluding != "" && version <= cpe.VersionStartExcluding {
		//fmt.Printf("Failed match, version %v, e Including %v\n", version, cpe.VersionEndExcluding)
		return false
	}
	if cpe.VersionEndIncluding != "" && version > cpe.VersionEndIncluding {
		//fmt.Printf("Failed match, version %v, excluding %v\n", version, cpe.VersionEndIncluding)
		return false
	}
	if cpe.VersionEndExcluding != "" && version >= cpe.VersionEndExcluding {
		//fmt.Printf("Failed match, version %v, e excluding %v\n", version, cpe.VersionEndExcluding)
		return false
	}

	return matched
}

func cpeMatch(cpes []*CVECPEMatch, cpePattern string, operator string,
	children []*CVENodes, negates string) bool {
	var result bool

	if cpePattern == "" {
		return false
	}

	if len(children) == 0 {
		switch operator {
		case "OR":
			for _, cpe := range cpes {
				matched := versionMatch(cpe, cpePattern, *version)
				//fmt.Printf("c:OR: Matching cpe %v, negates %v\n", cpe, negates)
				if matched == true && cpe.Vulnerable == true &&
					(negates == "" || negates == "false") {
					//fmt.Printf("c:OR: true\n")
					return true
				}
			}
			//fmt.Printf("c:OR: false\n")
			return false
		case "AND":
			for _, cpe := range cpes {
				matched := versionMatch(cpe, cpePattern, *version)
				//fmt.Printf("c:AND: Matching cpe %v, negates %v\n", cpe, negates)
				if matched == false || cpe.Vulnerable == false ||
					(negates == "" && negates == "false") {
					//fmt.Printf("c:AND: false\n")
					return false
				}
			}
			//fmt.Printf("c:AND: true\n")
			return true
		}
	}

	switch operator {
	case "OR":
		for _, childcpe := range children {
			result = cpeMatch(childcpe.CPEMatch, cpePattern, childcpe.CVEOperator,
				childcpe.CVEChildren, childcpe.CVENegates)
			if result == true {
				//fmt.Printf("OR: true\n")
				return true
			}
		}
		//fmt.Printf("OR: false\n")
		return false
	case "AND":
		for _, childcpe := range children {
			result = cpeMatch(childcpe.CPEMatch, cpePattern, childcpe.CVEOperator,
				childcpe.CVEChildren, childcpe.CVENegates)
			if result == false {
				//fmt.Printf("AND: false\n")
				return false
			}
		}
		//fmt.Printf("AND: true\n")
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

// nvdcve-1.1-recent is a valid feed as well :)
var cveJSONFeedURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

//var cveJSONFeedURL = "file:///tmp/nvdcve-1.1-%s.json.gz"

func getJSONFeed(url string) (resp io.ReadCloser, err error) {

	var webresp *http.Response

	if strings.HasPrefix(url, "file:///") {
		url = strings.TrimLeft(url, "file:")
		r, err := os.Open(url)
		if err != nil {
			log.Fatal("Could not open ", url)
		}
		resp = r
	} else {
		webresp, err = http.Get(url)
		if err != nil {
			return nil, err
		}

		if webresp.StatusCode != http.StatusOK {
			resp.Close()
			return nil, fmt.Errorf("Can't contact the URL for feeds %s", url)
		}

		resp = webresp.Body
	}

	return resp, nil
}

func main() {
	var result CVEMain

	uniquecves := make(map[string]bool)
	flag.Parse()

	cveJSONFeedURL = fmt.Sprintf(cveJSONFeedURL, *year)
	fmt.Printf("Fetching feed from %s to match %s\n", cveJSONFeedURL, *cpe)
	resp, err := getJSONFeed(cveJSONFeedURL)
	if err != nil {
		log.Fatal(err)
		return
	}

	reader, err := gzip.NewReader(resp)
	if err != nil {
		fmt.Printf("%s\n", err)
		log.Fatal("Failed to parse gzipped JSON file")
		resp.Close()
	}

	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		fmt.Printf("%s\n", err)
		log.Fatal("Failed to parse JSON file")
		resp.Close()
	}

	//fmt.Printf("%v", result.CVEItems)
	for _, item := range result.CVEItems {

		for _, node := range item.Configuration.CVENodes {

			if cpeMatch(node.CPEMatch, *cpe, node.CVEOperator,
				node.CVEChildren, node.CVENegates) &&
				uniquecves[item.CVEInfo.MetaData.ID] == false {

				fmt.Printf("\n%v: %v", item.CVEInfo.MetaData.ID,
					item.CVEInfo.Description.Description[0].Value)

				fmt.Printf(" %v %v %v\n", item.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
					item.Impact.BaseMetricV3.CVSSV3.BaseScore,
					item.Impact.BaseMetricV3.CVSSV3.VectorString)

				uniquecves[item.CVEInfo.MetaData.ID] = true
			}

			if *keyword == "" {
				break
			}

			if descMatch(item.CVEInfo.Description.Description, *keyword) &&
				uniquecves[item.CVEInfo.MetaData.ID] == false {

				fmt.Printf("\n%v: %v", item.CVEInfo.MetaData.ID,
					item.CVEInfo.Description.Description[0].Value)

				fmt.Printf(" %v %v %v\n", item.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
					item.Impact.BaseMetricV3.CVSSV3.BaseScore,
					item.Impact.BaseMetricV3.CVSSV3.VectorString)

				uniquecves[item.CVEInfo.MetaData.ID] = true
			}
		}
	}

	resp.Close()
}

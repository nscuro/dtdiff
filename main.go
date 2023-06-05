package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/nsf/jsondiff"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type comparisonPair struct {
	aProject dtrack.Project
	bProject dtrack.Project
}

func main() {
	var (
		aURL        string
		aAPIKey     string
		bURL        string
		bAPIKey     string
		concurrency int
		outDir      string
	)
	flag.StringVar(&aURL, "url-a", "", "API URL for Dependency-Track instance A")
	flag.StringVar(&aAPIKey, "apikey-a", "", "API URL for Dependency-Track instance A")
	flag.StringVar(&bURL, "url-b", "", "API URL for Dependency-Track instance B")
	flag.StringVar(&bAPIKey, "apikey-b", "", "API key for Dependency-Track instance B")
	flag.IntVar(&concurrency, "concurrency", 5, "Maximum comparison concurrency")
	flag.StringVar(&outDir, "out", "", "Path to write output files to")
	flag.Parse()

	aClient, err := dtrack.NewClient(aURL, dtrack.WithAPIKey(aAPIKey))
	if err != nil {
		log.Fatalf("failed to initialize client for %s: %v", aURL, err)
	}

	bClient, err := dtrack.NewClient(bURL, dtrack.WithAPIKey(bAPIKey))
	if err != nil {
		log.Fatalf("failed to initialize client for %s: %v", bURL, err)
	}

	log.Printf("collecting projects from %s", aURL)
	aProjects, err := collectProjects(aClient)
	if err != nil {
		log.Fatalf("failed to collect projects from %s: %v", aURL, err)
	}

	log.Printf("collected %d projects from %s", len(aProjects), aURL)
	if len(aProjects) == 0 {
		log.Println("nothing to do")
		return
	}

	log.Println("match projects from %s with projects in %s", aURL, bURL)
	comparisonPairs, err := matchProjectComparisonPairs(bClient, aProjects)
	if err != nil {
		log.Fatalf("failed to match projects from %s with projects in %s: %v", aURL, bURL, err)
	}

	if len(comparisonPairs) == 0 {
		log.Printf("no project from %s matches any project in %s", aURL, bURL)
		return
	}

	wg := sync.WaitGroup{}
	pairChan := make(chan comparisonPair, 1)

	log.Printf("launching %d comparison workers", concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go doCompare(pairChan, &wg, aClient, bClient, outDir)
	}

	for _, pair := range comparisonPairs {
		pairChan <- pair
	}
	close(pairChan)

	wg.Wait()
	log.Println("all done")
}

func collectProjects(c *dtrack.Client) ([]dtrack.Project, error) {
	projects := make([]dtrack.Project, 0)

	err := dtrack.ForEach(
		func(po dtrack.PageOptions) (dtrack.Page[dtrack.Project], error) {
			return c.Project.GetAll(context.Background(), po)
		},
		func(project dtrack.Project) error {
			projects = append(projects, project)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return projects, nil
}

func matchProjectComparisonPairs(c *dtrack.Client, projects []dtrack.Project) ([]comparisonPair, error) {
	pairs := make([]comparisonPair, 0)

	for _, project := range projects {
		match, err := c.Project.Lookup(context.Background(), project.Name, project.Version)
		if err != nil {
			var apiErr *dtrack.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
				log.Printf("failed to lookup project %s/%s: %v", project.Name, project.Version, err)
			}

			continue
		}

		pairs = append(pairs, comparisonPair{
			aProject: project,
			bProject: match,
		})
	}

	return pairs, nil
}

func doCompare(pairs <-chan comparisonPair, wg *sync.WaitGroup, ac, bc *dtrack.Client, outDir string) {
	defer wg.Done()

	for pair := range pairs {
		log.Printf("comparing findings for %s/%s", pair.aProject.Name, pair.aProject.Version)

		aFindingPage, err := ac.Finding.GetAll(context.Background(), pair.aProject.UUID, true, dtrack.PageOptions{})
		if err != nil {
			log.Printf("failed to fetch findings for %s/%s from %s: %v", pair.aProject.Name, pair.aProject.Version, ac.BaseURL(), err)
			continue
		}

		bFindingPage, err := bc.Finding.GetAll(context.Background(), pair.bProject.UUID, true, dtrack.PageOptions{})
		if err != nil {
			log.Printf("failed to fetch findings for %s/%s from %s: %v", pair.bProject.Name, pair.bProject.Version, bc.BaseURL(), err)
			continue
		}

		// Null-ify fields that will always be different due to their dynamic nature.
		// This will include UUIDs, timestamps, etc.
		clearDynamicFields(aFindingPage.Items)
		clearDynamicFields(bFindingPage.Items)

		// Sort findings by component name and vulnerability ID so that the diff will
		// not be polluted with positional differences.
		sort.SliceStable(aFindingPage.Items, sortCompareFindings(aFindingPage.Items))
		sort.SliceStable(bFindingPage.Items, sortCompareFindings(bFindingPage.Items))

		aFindings, err := json.Marshal(aFindingPage.Items)
		if err != nil {
			log.Printf("failed to export fpf for %s/%s from %s: %v", pair.aProject.Name, pair.aProject.Version, bc.BaseURL(), err)
			continue
		}

		bFindings, err := json.Marshal(bFindingPage.Items)
		if err != nil {
			log.Printf("failed to export fpf for %s/%s from %s: %v", pair.bProject.Name, pair.bProject.Version, bc.BaseURL(), err)
			continue
		}

		// Canonicalize the JSON to ensure an even more clean diff.
		aFindingsJCS, err := jcs.Transform(aFindings)
		if err != nil {
			log.Printf("failed to canonicalize fpf for %s/%s from %s: %v", pair.aProject.Name, pair.aProject.Version, ac.BaseURL(), err)
			continue
		}
		bFindingsJCS, err := jcs.Transform(bFindings)
		if err != nil {
			log.Printf("failed to canonicalize fpf for %s/%s from %s: %v", pair.bProject.Name, pair.bProject.Version, bc.BaseURL(), err)
			continue
		}

		diffOpts := jsondiff.DefaultHTMLOptions()
		diffType, diffStr := jsondiff.Compare(aFindingsJCS, bFindingsJCS, &diffOpts)
		if diffType != jsondiff.FullMatch {
			log.Printf("findings for %s/%s are different", pair.aProject.Name, pair.aProject.Version)
			diffPath := filepath.Join(outDir, strings.ReplaceAll(fmt.Sprintf("%s_%s.html", pair.aProject.Name, pair.aProject.Version), "/", "-"))
			err = os.WriteFile(diffPath, []byte(fmt.Sprintf("<pre>%s</pre>", diffStr)), os.ModePerm)
			if err != nil {
				log.Printf("failed to write diff output: %v", err)
			}
		} else {
			log.Printf("findings for %s/%s are equal", pair.aProject.Name, pair.aProject.Version)
		}
	}
}

func sortCompareFindings(findings []dtrack.Finding) func(int, int) bool {
	return func(i int, j int) bool {
		fl := findings[i]
		fr := findings[j]

		if fl.Component.Name == fr.Component.Name {
			return fl.Vulnerability.VulnID < fr.Vulnerability.VulnID
		}

		return fl.Component.Name < fr.Component.Name
	}
}

func clearDynamicFields(findings []dtrack.Finding) {
	for i := range findings {
		findings[i].Component.UUID = uuid.Nil
		findings[i].Component.Project = uuid.Nil
		findings[i].Vulnerability.UUID = uuid.Nil
		findings[i].Attribution.UUID = uuid.Nil
		findings[i].Attribution.AttributedOn = 0
		findings[i].Matrix = ""
	}
}

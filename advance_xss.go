package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Function to read lines from a file
func readLines(filePath string) ([]string, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	var lines []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// Function to scrape the page for parameters and form fields
func scrapeParameters(url string, verbose bool) ([]string, error) {
	var parameters []string
	var mu sync.Mutex

	// Initialize Colly collector
	c := colly.NewCollector()

	// Scrape URL parameters from the HTML
	c.OnHTML("form", func(e *colly.HTMLElement) {
		e.ForEach("input[name]", func(_ int, el *colly.HTMLElement) {
			param := el.Attr("name")
			if param != "" {
				mu.Lock()
				parameters = append(parameters, param)
				mu.Unlock()
				if verbose {
					fmt.Printf("Found parameter: %s\n", param)
				}
			}
		})
	})

	// Start scraping
	if err := c.Visit(url); err != nil {
		return nil, err
	}

	return parameters, nil
}

// Function to test for reflected XSS (GET and POST)
func testXSS(targetURL string, params []string, payloads []string, wg *sync.WaitGroup, verbose bool) {
	defer wg.Done()

	client := &http.Client{}
	for _, param := range params {
		for _, payload := range payloads {
			// Test GET request first
			testURL := fmt.Sprintf("%s?%s=%s", targetURL, param, url.QueryEscape(payload))
			if verbose {
				fmt.Printf("Testing GET: %s\n", testURL)
			}
			resp, err := client.Get(testURL)
			if err != nil {
				fmt.Printf("Error sending GET request to %s: %v\n", testURL, err)
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Printf("Error reading GET response body: %v\n", err)
				continue
			}

			if strings.Contains(string(body), payload) {
				color.Red("XSS Vulnerability Found!")
				color.Red("URL: %s", testURL)
				color.Red("Payload: %s\n", payload)
				return
			}

			// Test POST request
			formData := url.Values{}
			formData.Set(param, payload)
			if verbose {
				fmt.Printf("Testing POST: %s with data %v\n", targetURL, formData)
			}
			resp, err = client.PostForm(targetURL, formData)
			if err != nil {
				fmt.Printf("Error sending POST request: %v\n", err)
				continue
			}

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Printf("Error reading POST response body: %v\n", err)
				continue
			}

			if strings.Contains(string(body), payload) {
				color.Red("XSS Vulnerability Found!")
				color.Red("URL: %s", targetURL)
				color.Red("Payload: %s\n", payload)
				return
			}
		}
	}
}

func main() {
	// Define and parse flags
	urlsFile := flag.String("u", "", "Path to file containing target URLs")
	payloadsFile := flag.String("p", "", "Path to file containing payloads")
	verbose := flag.Bool("v", false, "Enable verbose mode")
	help := flag.Bool("h", false, "Show help message")
	flag.Parse()

	if *help || *urlsFile == "" || *payloadsFile == "" {
		fmt.Println("Created By MOAZAM HAMEED")
		fmt.Println("Usage: xss_auto -u <urls_file> -p <payloads_file> [-v]")
		fmt.Println("\nOptions:")
		fmt.Println("  -u    Path to file containing target URLs")
		fmt.Println("  -p    Path to file containing payloads")
		fmt.Println("  -v    Enable verbose mode")
		fmt.Println("  -h    Show this help message")
		return
	}

	// Read URLs and payloads
	urls, err := readLines(*urlsFile)
	if err != nil {
		fmt.Printf("Error reading URLs: %v\n", err)
		return
	}

	payloads, err := readLines(*payloadsFile)
	if err != nil {
		fmt.Printf("Error reading payloads: %v\n", err)
		return
	}

	// Test each URL
	for _, targetURL := range urls {
		fmt.Printf("\nTesting XSS on: %s\n", targetURL)
		color.Cyan("Scraping parameters for: %s\n", targetURL)

		scrapedParams, err := scrapeParameters(targetURL, *verbose)
		if err != nil {
			fmt.Printf("Error scraping parameters: %v\n", err)
			continue
		}

		var wg sync.WaitGroup
		for _, param := range scrapedParams {
			wg.Add(1)
			go testXSS(targetURL, []string{param}, payloads, &wg, *verbose)
		}

		wg.Wait()
	}
}

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	// ASCII Art Header
	printHeader()

	// Read domain names from user
	fmt.Print("Enter domain names (comma-separated for multiple): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	input := scanner.Text()
	domains := strings.Split(input, ",")

	// Create results directory
	timestamp := time.Now().Format("20060102_150405")
	outputDir := fmt.Sprintf("results/run_%s", timestamp)
	os.MkdirAll(outputDir, os.ModePerm)

	// Process each domain
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		domainOutput := fmt.Sprintf("%s/%s", outputDir, domain)
		os.MkdirAll(domainOutput, os.ModePerm)

		fmt.Printf("Starting recon for domain: %s\n", domain)

		// Subdomain Enumeration
		executeCommand(fmt.Sprintf("subfinder -d %s | anew %s/subdomains.txt", domain, domainOutput))
		executeCommand(fmt.Sprintf("assetfinder --subs-only %s | anew %s/subdomains.txt", domain, domainOutput))
		executeCommand(fmt.Sprintf("sort -u %s/subdomains.txt > %s/Genesis-Sub.txt", domainOutput, domainOutput))

		// Active Subdomain Check
		executeCommand(fmt.Sprintf("cat %s/Genesis-Sub.txt | httpx -o %s/Genesis-live.txt", domainOutput, domainOutput))

		// URL Collection
		waybackDir := fmt.Sprintf("%s/wayback", domainOutput)
		gauDir := fmt.Sprintf("%s/gau", domainOutput)
		os.MkdirAll(waybackDir, os.ModePerm)
		os.MkdirAll(gauDir, os.ModePerm)
		executeCommand(fmt.Sprintf("echo %s | waybackurls | anew %s/wayback-url.txt", domain, waybackDir))
		executeCommand(fmt.Sprintf("echo %s | gau | anew %s/gau-urls.txt", domain, gauDir))

		// Merge and Filter URLs
		pathsFile := fmt.Sprintf("%s/paths.txt", domainOutput)
		executeCommand(fmt.Sprintf("cat %s/wayback/wayback-url.txt %s/gau/gau-urls.txt | anew %s", waybackDir, gauDir, pathsFile))
		executeCommand(fmt.Sprintf("cat %s | uro -o %s/Final-URO/uro-filtered.txt", pathsFile, domainOutput))

		// Check live endpoints
		executeCommand(fmt.Sprintf("httpx -l %s/Final-URO/uro-filtered.txt -o %s/Final-Live/URL-LIVE.txt -threads 200 -silent", domainOutput, domainOutput))

		// Filter specific file types
		filterFiles(domainOutput, "PHP-Files", "\\.php$")
		filterFiles(domainOutput, "JSON-Files", "\\.json$")
		filterFiles(domainOutput, "Env-Files", "\\.env$")
		filterFiles(domainOutput, "Log-Files", "\\.log$")

		fmt.Printf("Recon process for %s completed. Results saved in %s.\n", domain, domainOutput)
	}

	fmt.Println("All recon processes completed.")
}

func printHeader() {
	fmt.Println("\033[1;32m")
	fmt.Println("██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  ██████╗  ██████╗ ")
	fmt.Println("██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚════██╗██╔════╝ ██╔═████╗")
	fmt.Println("██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ █████╔╝███████╗ ██║██╔██║")
	fmt.Println("██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ╚═══██╗██╔═══██╗████╔╝██║")
	fmt.Println("██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝╚██████╔╝")
	fmt.Println("╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚═════╝")
	fmt.Println("---------------------------------------------------------------------")
	fmt.Println("Developed By Narayanan K - [ Advanced Bug bounty Hunting Recon Tool Kit ]")
	fmt.Println("\033[0m")
}

func executeCommand(cmd string) {
	fmt.Printf("Executing: %s\n", cmd)
	command := exec.Command("bash", "-c", cmd)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		os.Exit(1)
	}
}

func filterFiles(outputDir, subDir, regex string) {
	dir := fmt.Sprintf("%s/%s", outputDir, subDir)
	os.MkdirAll(dir, os.ModePerm)
	cmd := fmt.Sprintf("grep \"%s\" %s/Final-Live/URL-LIVE.txt > %s/%s-files.txt", regex, outputDir, dir, strings.TrimSuffix(subDir, "-Files"))
	executeCommand(cmd)
}

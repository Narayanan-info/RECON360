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

	// Install required tools if missing
	requiredTools := []string{"subfinder", "assetfinder", "httpx", "waybackurls", "gau", "anew"}
	for _, tool := range requiredTools {
		if !isToolInstalled(tool) {
			fmt.Printf("Tool %s is not installed. Installing...\n", tool)
			installTool(tool)
		} else {
			fmt.Printf("Tool %s is already installed.\n", tool)
		}
	}

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
		executeCommand(fmt.Sprintf("cat %s/wayback-url.txt %s/gau-urls.txt | anew %s", waybackDir, gauDir, pathsFile))

		// Check live endpoints
		finalLiveDir := fmt.Sprintf("%s/Final-Live", domainOutput)
		os.MkdirAll(finalLiveDir, os.ModePerm)
		executeCommand(fmt.Sprintf("httpx -l %s/paths.txt -o %s/URL-LIVE.txt -threads 200 -silent", domainOutput, finalLiveDir))

		// Filter specific file types
		filterFiles(domainOutput, "PHP-Files", "\\.php$")
		filterFiles(domainOutput, "JSON-Files", "\\.json$")
		filterFiles(domainOutput, "Env-Files", "\\.env$")
		filterFiles(domainOutput, "JS-Files", "\\.js$")
		filterFiles(domainOutput, "Aspx-Files", "\\.aspx$")
		filterFiles(domainOutput, "PDF-Files", "\\.pdf$")
		filterFiles(domainOutput, "CSV-Files", "\\.csv$")
		filterFiles(domainOutput, "TXT-Files", "\\.txt$")
		filterFiles(domainOutput, "Xlsx-Files", "\\.xlsx$")
		filterFiles(domainOutput, "LOG-Files", "\\.log$")
		filterFiles(domainOutput, "Zip-Files", "\\.zip$")

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

func isToolInstalled(tool string) bool {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("command -v %s", tool))
	err := cmd.Run()
	return err == nil
}

func installTool(tool string) {
	var installCommand string
	switch tool {
	case "subfinder":
		installCommand = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
	case "anew":
		installCommand = "go install -v github.com/tomnomnom/anew@latest"
	case "assetfinder":
		installCommand = "go install github.com/tomnomnom/assetfinder@latest"
	case "httpx":
		installCommand = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
	case "waybackurls":
		installCommand = "go install github.com/tomnomnom/waybackurls@latest"
	case "gau":
		installCommand = "go install github.com/lc/gau@latest"
	default:
		fmt.Printf("Unknown tool: %s\n", tool)
		return
	}

	fmt.Printf("Installing %s...\n", tool)
	command := exec.Command("bash", "-c", installCommand)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Printf("Error installing %s: %s\n", tool, err)
		os.Exit(1)
	}
}

func filterFiles(outputDir, subDir, regex string) {
	dir := fmt.Sprintf("%s/%s", outputDir, subDir)
	os.MkdirAll(dir, os.ModePerm)
	cmd := fmt.Sprintf("grep \"%s\" %s/Final-Live/URL-LIVE.txt > %s/%s-files.txt", regex, outputDir, dir, strings.TrimSuffix(subDir, "-Files"))
	executeCommand(cmd)
}

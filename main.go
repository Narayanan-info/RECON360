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
	requiredTools := []string{"subfinder", "assetfinder", "httpx", "waybackurls", "gau", "anew", "gospider", "hakrawler", "katana"}
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
		gospiderDir := fmt.Sprintf("%s/gospider", domainOutput)
		hakrawlerDir := fmt.Sprintf("%s/hakrawler", domainOutput)
		katanaDir := fmt.Sprintf("%s/katana", domainOutput)

		os.MkdirAll(waybackDir, os.ModePerm)
		os.MkdirAll(gauDir, os.ModePerm)
		os.MkdirAll(gospiderDir, os.ModePerm)
		os.MkdirAll(hakrawlerDir, os.ModePerm)
		os.MkdirAll(katanaDir, os.ModePerm)

		// Corrected Commands
		executeCommand(fmt.Sprintf("cat %s/Genesis-live.txt | waybackurls | anew %s/wayback-url.txt", domainOutput, waybackDir))
		executeCommand(fmt.Sprintf("cat %s/Genesis-live.txt | gau | anew %s/gau-urls.txt", domainOutput, gauDir))
		executeCommand(fmt.Sprintf("cat %s/Genesis-live.txt | gospider -c 10 -d 5 -t 20 --blacklist '(?i)\\.(jpg|jpeg|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$' --other-source --timeout 10 | grep -e 'code-200' | awk '{print $5}' | grep '=' | anew %s/gospider-urls.txt", domainOutput, gospiderDir))
		executeCommand(fmt.Sprintf("cat %s/Genesis-live.txt | hakrawler -d 10 | grep '=' | egrep -i '\\.(jpg|jpeg|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$' --invert-match | anew %s/hakrawler-urls.txt", domainOutput, hakrawlerDir))
		executeCommand(fmt.Sprintf("cat %s/Genesis-live.txt | katana -f url -d 10 | anew %s/katana-urls.txt", domainOutput, katanaDir))

		// Merge and Filter URLs
		pathsFile := fmt.Sprintf("%s/paths.txt", domainOutput)
		executeCommand(fmt.Sprintf("cat %s/wayback-url.txt %s/gau-urls.txt %s/gospider-urls.txt %s/hakrawler-urls.txt %s/katana-urls.txt | anew %s", waybackDir, gauDir, gospiderDir, hakrawlerDir, katanaDir, pathsFile))

		// Check live endpoints
		finalLiveDir := fmt.Sprintf("%s/Final-Live", domainOutput)
		os.MkdirAll(finalLiveDir, os.ModePerm)
		executeCommand(fmt.Sprintf("httpx -l %s/paths.txt -o %s/URL-LIVE.txt -threads 200 -silent", domainOutput, finalLiveDir))

		// Remove duplicate URLs
		uniqueFile := fmt.Sprintf("%s/URL-LIVE-UNIQUE.txt", finalLiveDir)
		executeCommand(fmt.Sprintf("sort %s/URL-LIVE.txt | uniq > %s", finalLiveDir+"/URL-LIVE.txt", uniqueFile))

		// Check live endpoints
		OpenRedirectDir := fmt.Sprintf("%s/Open-Redirect", domainOutput)
		os.MkdirAll(OpenRedirectDir, os.ModePerm)

		// Use the correct path for URL-LIVE.txt
		liveURLFile := fmt.Sprintf("%s/URL-LIVE-UNIQUE.txt", finalLiveDir)
		redirectParamsFile := fmt.Sprintf("%s/redirect_params.txt", OpenRedirectDir)

		// Correctly escape quotes in the grep command
		grepCommand := fmt.Sprintf(`grep -E \"url=|redirect=|next=|return=|destination=|dest=|window=|reference=|data=|html=|to=|goto=|out=|path=|view=|continue=|rurl=|rdr=|redir=|u=|ref=|refer=|site=|uri=|link=|callback=|forward=|forwardTo=|go=|target=|returnTo=|return_url=|redirect_uri=|redirect_url=|redirectTo=|RelayState=\" %s > %s`, liveURLFile, redirectParamsFile)
		executeCommand(grepCommand)

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
	fmt.Println("██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗  ██████╗  ██████╗ ")
	fmt.Println("██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ ██╔════╝ ██╔═████╗")
	fmt.Println("██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ███████╗ ██║██╔██║")
	fmt.Println("██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔═══██╗████╔╝██║")
	fmt.Println("██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║ ╚██████╔╝╚██████╔╝")
	fmt.Println("╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  ╚═════╝  ╚═════╝ ")
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
		installCommand = "go install -v github.com/tomnomnom/assetfinder@latest"
	case "httpx":
		installCommand = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
	case "waybackurls":
		installCommand = "go install -v github.com/tomnomnom/waybackurls@latest"
	case "gau":
		installCommand = "go install -v github.com/lc/gau@latest"
	case "gospider":
		installCommand = "go install -v github.com/jaeles-project/gospider@latest"
	case "hakrawler":
		installCommand = "go install -v github.com/hakluke/hakrawler@latest"
	case "katana":
		installCommand = "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"

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
	// Construct the directory path
	dir := fmt.Sprintf("%s/%s", outputDir, subDir)

	// Ensure the output directory exists
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Printf("Error creating directory %s: %v\n", dir, err)
		return
	}

	// Construct the output file path
	outputFile := fmt.Sprintf("%s/%s-files.txt", dir, strings.TrimSuffix(subDir, "-Files"))

	// Construct the grep command with a fallback to avoid errors
	cmd := fmt.Sprintf("grep \"%s\" %s/Final-Live/URL-LIVE.txt > %s || true", regex, outputDir, outputFile)

	// Execute the command
	executeCommand(cmd)
	if err != nil {
		fmt.Printf("No matches found for pattern '%s'. Skipping...\n", regex)
	} else {
		fmt.Printf("Filtered files for pattern '%s' saved to %s\n", regex, outputFile)
	}
}

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	EPERM     = 1
	ENOENT    = 2
	ETIMEDOUT = 110
)

func printUsageAndExit(name, conf string) {
	fmt.Printf("usage:\n\t%s %s\n", name, conf)
	os.Exit(1)
}

func parseArg() string {
	confFile := "config.json"
	args := os.Args

	if len(args) == 2 {
		arg := args[1]
		switch arg {
		case "-h", "--help":
			printUsageAndExit(args[0], confFile)
		default:
			confFile = arg
		}
	} else if len(args) > 2 {
		printUsageAndExit(args[0], confFile)
	}

	return confFile
}

func main() {
	// Initialize logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	printVersion()
	checkPrivilege()

	confFile := parseArg()
	conf, err := ConfigFromFile(confFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	name := *conf.InterfaceName
	useVPNDNS := false
	if conf.UseVPNDNS != nil {
		useVPNDNS = *conf.UseVPNDNS
	}

	// Handle server configuration
	if conf.Server == nil {
		companyURL, err := GetCompanyURL(conf.CompanyName)
		if err != nil {
			log.Fatalf("Failed to fetch company server: %v", err)
		}
		log.Printf("Company name is %s(zh)/%s(en) server is %s",
			companyURL.ZhName, companyURL.EnName, companyURL.Domain)
		conf.Server = &companyURL.Domain
		if err := conf.Save(); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
	}

	withWgLog := false
	if conf.DebugWg != nil {
		withWgLog = *conf.DebugWg
	}

	client, err := NewClient(conf)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	logoutRetry := true
	var wgConf *WgConf

	// Connection loop
	for {
		if client.NeedLogin() {
			log.Println("Not login yet, try to login")
			if err := client.Login(); err != nil {
				log.Fatalf("Login failed: %v", err)
			}
			log.Println("Login success")
		}

		log.Println("Try to connect")
		conf, err := client.ConnectVPN()
		if err != nil {
			if logoutRetry && strings.Contains(err.Error(), "logout") {
				log.Printf("Warning: %v", err)
				logoutRetry = false
				continue
			}
			log.Fatalf("Connection failed: %v", err)
		}
		wgConf = conf
		break
	}

	log.Printf("Start wg-corplink for %s", name)

	if !StartWgGo(name, int(wgConf.Protocol), withWgLog) {
		log.Printf("Failed to start wg-corplink for %s", name)
		os.Exit(EPERM)
	}

	uapi := &UAPIClient{Name: name}
	if err := uapi.ConfigureWG(wgConf); err != nil {
		log.Printf("Failed to config interface with uapi for %s: %v", name, err)
		os.Exit(EPERM)
	}

	var dnsManager *DNSManager
	if useVPNDNS {
		dnsManager = NewDNSManager()
		if err := dnsManager.SetDNS([]string{wgConf.DNS}, nil); err != nil {
			log.Printf("Failed to set DNS: %v", err)
		}
	}

	// Setup signal handling and connection monitoring
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	exitCode := 0
	select {
	case <-sigChan:
		log.Println("Signal received, shutting down")
	case <-time.After(60 * time.Second):
		if err := client.KeepAliveVPN(wgConf, 60); err != nil {
			exitCode = ETIMEDOUT
		}
	case <-func() chan bool {
		ch := make(chan bool)
		go func() {
			uapi.CheckWgConnection()
			ch <- true
		}()
		return ch
	}():
		log.Println("Last handshake timeout")
		exitCode = ETIMEDOUT
	}

	// Cleanup
	log.Println("Disconnecting VPN...")
	if err := client.DisconnectVPN(wgConf); err != nil {
		log.Printf("Failed to disconnect VPN: %v", err)
	}

	StopWgGo()

	if useVPNDNS && dnsManager != nil {
		if err := dnsManager.RestoreDNS(); err != nil {
			log.Printf("Failed to restore DNS: %v", err)
		}
	}

	log.Println("Reach exit")
	os.Exit(exitCode)
}

func checkPrivilege() {
	if os.Geteuid() != 0 {
		log.Fatal("Please run as root")
	}
}

func printVersion() {
	pkgName := os.Getenv("CARGO_PKG_NAME")
	if pkgName == "" {
		pkgName = "corplink"
	}
	pkgVersion := os.Getenv("CARGO_PKG_VERSION")
	if pkgVersion == "" {
		pkgVersion = "dev"
	}
	log.Printf("Running %s@%s", pkgName, pkgVersion)
}

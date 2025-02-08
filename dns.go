package main

import (
	"log"
	"os/exec"
	"strings"
)

type DNSManager struct {
	serviceDNS       map[string]string
	serviceDNSSearch map[string]string
}

func NewDNSManager() *DNSManager {
	return &DNSManager{
		serviceDNS:       make(map[string]string),
		serviceDNSSearch: make(map[string]string),
	}
}

func (dm *DNSManager) collectNewServiceDNS() error {
	output, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return err
	}

	services := strings.Split(strings.TrimSpace(string(output)), "\n")
	// Skip the first line's legend
	for _, service := range services[1:] {
		// Remove leading '*' and trim whitespace
		service = strings.TrimSpace(strings.TrimPrefix(service, "*"))
		if service == "" {
			continue
		}

		// Get DNS servers
		dnsOutput, err := exec.Command("networksetup", "-getdnsservers", service).Output()
		if err != nil {
			return err
		}
		dnsResponse := strings.TrimSpace(string(dnsOutput))
		if strings.Contains(dnsResponse, " ") {
			dnsResponse = "Empty"
		}

		dm.serviceDNS[service] = dnsResponse

		// Get search domain
		searchOutput, err := exec.Command("networksetup", "-getsearchdomains", service).Output()
		if err != nil {
			return err
		}
		searchResponse := strings.TrimSpace(string(searchOutput))
		if strings.Contains(searchResponse, " ") {
			searchResponse = "Empty"
		}

		dm.serviceDNSSearch[service] = searchResponse

		log.Printf("DNS collected for %s, dnsservers: %s, search domain: %s",
			service, dnsResponse, searchResponse)
	}
	return nil
}

func (dm *DNSManager) SetDNS(dnsServers []string, dnsSearch []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	if err := dm.collectNewServiceDNS(); err != nil {
		return err
	}

	for service := range dm.serviceDNS {
		args := append([]string{"-setdnsservers", service}, dnsServers...)
		cmd := exec.Command("networksetup", args...)
		if err := cmd.Run(); err != nil {
			return err
		}

		if len(dnsSearch) > 0 {
			args = append([]string{"-setsearchdomains", service}, dnsSearch...)
			cmd = exec.Command("networksetup", args...)
			if err := cmd.Run(); err != nil {
				return err
			}
		}

		log.Printf("DNS set for %s with %s", service, strings.Join(dnsServers, ","))
	}

	return nil
}

func (dm *DNSManager) RestoreDNS() error {
	for service, dns := range dm.serviceDNS {
		args := append([]string{"-setdnsservers", service}, strings.Split(dns, "\n")...)
		cmd := exec.Command("networksetup", args...)
		if err := cmd.Run(); err != nil {
			return err
		}

		log.Printf("DNS server reset for %s with %s", service, dns)
	}

	for service, searchDomain := range dm.serviceDNSSearch {
		args := append([]string{"-setsearchdomains", service}, strings.Split(searchDomain, "\n")...)
		cmd := exec.Command("networksetup", args...)
		if err := cmd.Run(); err != nil {
			return err
		}

		log.Printf("DNS search domain reset for %s with %s", service, searchDomain)
	}

	log.Println("DNS reset")
	return nil
}

package client

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Use these helpers in your solution

const (
	//
	// Constants related to the lab setup:
	//
	AttackSeconds = 10
	// This is how long the victim will measure incoming packets. It is recommended to
	// terminate your attack after the measurement period such that the remote victim does not confuse
	// the attack boundaries. During grading, your client will be stopped automatically after this time.
	AttackTime    = AttackSeconds * time.Second
	VictimScionIA = "17-ffaa:0:1115" // ISL-Victim AS
	VictimIP      = "100.0.0.1"      // Remote Victim IP
	AddressesFile = "IPs.yml"
	AddressesPath = "/etc/isl/"
	Addresses     = AddressesPath + AddressesFile

	//
	// Constants related to scion installation:
	//
	DispatcherPort       = 30041
	DispatcherConfigPath = "/etc/scion/dispatcher.toml"
	ScionTopologyPath    = "/etc/scion/topology.json"
	SciondConfigPath     = "/etc/scion/sciond.toml"
)

type Port struct {
	Port string `yaml:"victim_port"`
}

type LocalVictIP struct {
	IP net.IP `yaml:"local_victim_ip"`
}

type MeowIP struct {
	IP net.IP `yaml:"server_bridge_ip"`
}

/* MeowServerIP returns the student-specific IP address of the meow server */
func MeowServerIP() net.IP {
	if err := os.Chdir(AddressesPath); err != nil {
		log.Fatalf("Changing directory didn't work: %v", err)
	}
	var m *MeowIP
	yamlFile, err := ioutil.ReadFile(Addresses)
	if err != nil {
		log.Fatalf("Error reading meow server IP: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, &m)
	if err != nil {
		log.Fatalf("Error unmarshalling meow server IP: %v", err)
	}
	return m.IP
}

/* LocalVictimIP loads the local victim IP defined in IPs.yml.
 */
func LocalVictimIP() net.IP {
	if err := os.Chdir(AddressesPath); err != nil {
		log.Fatalf("Changing directory didn't work: %v", err)
	}
	var lvi *LocalVictIP
	yamlFile, err := ioutil.ReadFile(Addresses)
	if err != nil {
		log.Fatalf("Error reading local victim IP: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, &lvi)
	if err != nil {
		log.Fatalf("Error unmarshalling local victim IP: %v", err)
	}
	return lvi.IP
}

/*
Returns the remote victim IP
*/
func RemoteVictimIP() net.IP {
	return net.ParseIP(VictimIP)
}

/* VictimPort loads the port defined in IP.yml. Remote victim will multiplex on these ports
when reporting the attack volume back to you.
*/
func VictimPort() int {
	if err := os.Chdir(AddressesPath); err != nil {
		log.Fatalf("Changing directory didn't work: %v", err)
	}
	var p *Port
	yamlFile, err := ioutil.ReadFile(Addresses)
	if err != nil {
		log.Fatalf("Error reading port: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, &p)
	if err != nil {
		log.Fatalf("Unmarshal error: %v", err)
	}
	port, err := strconv.Atoi(p.Port)
	if err != nil {
		log.Fatalf("Conversion error: %v", err)
	}
	return port
}

/* DispatcherSocket finds the path of the dispatcher socket from the config file.
 */
func DispatcherSocket() (string, error) {
	file, err := os.Open(DispatcherConfigPath)
	if err != nil {
		return "", err
	}
	// Read file line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var socket = ""
	for scanner.Scan() {
		// Find Socket
		line := scanner.Text()
		if strings.Contains(line, "application_socket") {
			socket_start_idx := strings.Index(line, `"`) + 1
			socket = line[socket_start_idx : len(line)-1]
		}
	}
	// If no socket was specified in the config, return default socket
	if socket == "" {
		socket = "/run/shm/dispatcher/default.sock"
	}
	return socket, nil
}

/* SCIONDAddress finds the address of the scion daemon from the config file
 */
func SCIONDAddress() (string, error) {
	file, err := os.Open(SciondConfigPath)
	if err != nil {
		return "", err
	}
	// Read file line by line
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var addr = ""
	for scanner.Scan() {
		// Find addr
		line := scanner.Text()
		if strings.Contains(line, "address") {
			addr_start_idx := strings.Index(line, `"`) + 1
			addr = line[addr_start_idx : len(line)-1]
		}
	}
	return addr, nil
}

/* Extracts the Isolation Domain (ISD) and AS number from the topology configuration.
 */
func ISD_AS() (string, string) {
	var topology map[string]interface{}
	topo_byte, err := ioutil.ReadFile(ScionTopologyPath)
	if err != nil {
		log.Fatalf("Error reading topology file: %v", err)
	}
	json.Unmarshal([]byte(string(topo_byte)), &topology)
	isd_as := topology["isd_as"].(string)

	return strings.Split(isd_as, "-")[0], strings.Split(isd_as, "-")[1]
}

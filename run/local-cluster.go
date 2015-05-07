// Copyright 2015 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.
//
// Author: Peter Mattis (peter.mattis@gmail.com)

// Run using: go run local_cluster.go

// +build ignore

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fsouza/go-dockerclient"
)

const (
	dockerspyImage = "iverberk/docker-spy"
	domain         = "local"
)

var cockroachImage = flag.String("i", "cockroachdb/cockroach-dev", "the docker image to run")
var cockroachEntry = flag.String("e", "", "the entry point for the image")
var numNodes = flag.Int("n", 3, "the number of nodes to start")
var waitInterrupt = flag.Bool("w", false, "wait for an interrupt before existing")

func prettyJSON(v interface{}) string {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(pretty)
}

func newDockerClient() *docker.Client {
	client, err := docker.NewTLSClient(
		os.ExpandEnv("${DOCKER_HOST}"),
		os.ExpandEnv("${DOCKER_CERT_PATH}/cert.pem"),
		os.ExpandEnv("${DOCKER_CERT_PATH}/key.pem"),
		os.ExpandEnv("${DOCKER_CERT_PATH}/ca.pem"))
	if err != nil {
		log.Fatal(err)
	}
	return client
}

// remove a container (docker rm)
func remove(client *docker.Client, c *docker.Container) {
	err := client.RemoveContainer(docker.RemoveContainerOptions{
		ID:            c.ID,
		RemoveVolumes: true,
	})
	if err != nil {
		panic(err)
	}
}

// kill and remove a container (docker kill && docker rm)
func kill(client *docker.Client, c *docker.Container) {
	err := client.KillContainer(docker.KillContainerOptions{
		ID: c.ID,
	})
	if err != nil {
		panic(err)
	}
	remove(client, c)
}

// start a container (docker start)
func start(client *docker.Client, dns, c *docker.Container) {
	var dnsAddrs []string
	if dns != nil {
		dnsAddrs = append(dnsAddrs, dns.NetworkSettings.IPAddress)
	}
	err := client.StartContainer(c.ID, &docker.HostConfig{
		PublishAllPorts: true,
		DNS:             dnsAddrs,
	})
	if err != nil {
		panic(err)
	}
}

// wait for a container to exit (docker wait)
func wait(client *docker.Client, c *docker.Container) {
	code, err := client.WaitContainer(c.ID)
	if err != nil {
		panic(err)
	}
	if code != 0 {
		logs(client, c)
		panic(fmt.Errorf("non-zero exit code: %d", code))
	}
}

// retrieve the logs for a container (docker logs)
func logs(client *docker.Client, c *docker.Container) {
	err := client.Logs(docker.LogsOptions{
		Container:    c.ID,
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
		Stdout:       true,
		Stderr:       true,
	})
	if err != nil {
		panic(err)
	}
}

// inspect a container (docker inspect)
func inspect(client *docker.Client, cid string) *docker.Container {
	c, err := client.InspectContainer(cid)
	if err != nil {
		panic(err)
	}
	return c
}

// retrieve the ip address of docker itself
func dockerIP() string {
	u, err := url.Parse(os.ExpandEnv("${DOCKER_HOST}"))
	if err != nil {
		panic(err)
	}
	h, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		panic(err)
	}
	return h
}

// run docker-spy and return the started container
func runDockerSpy(client *docker.Client) *docker.Container {
	create := func() (*docker.Container, error) {
		return client.CreateContainer(docker.CreateContainerOptions{
			Name: "docker-spy",
			Config: &docker.Config{
				Image: dockerspyImage,
				Cmd:   []string{"--dns-domain=" + domain},
			},
		})
	}
	c, err := create()
	if err == docker.ErrNoSuchImage {
		err = client.PullImage(docker.PullImageOptions{
			Repository:   dockerspyImage,
			Tag:          "latest",
			OutputStream: os.Stdout,
		}, docker.AuthConfiguration{})
		c, err = create()
	}
	if err != nil {
		panic(err)
	}
	err = client.StartContainer(c.ID, &docker.HostConfig{
		Binds: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
		},
		PublishAllPorts: true,
	})
	if err != nil {
		panic(err)
	}
	c = inspect(client, c.ID)
	c.Name = "docker-spy"
	return c
}

func node(i int) string {
	return fmt.Sprintf("roach%d.%s", i, domain)
}

func data(i int) string {
	return fmt.Sprintf("/data%d", i)
}

// create the volumes container that keeps all of the volumes used by the
// cluster.
func createVolumes(client *docker.Client, numNodes int) *docker.Container {
	vols := map[string]struct{}{}
	for i := 0; i < numNodes; i++ {
		vols[data(i)] = struct{}{}
	}

	c, err := client.CreateContainer(docker.CreateContainerOptions{
		Config: &docker.Config{
			Image:   *cockroachImage,
			Volumes: vols,
		},
	})
	if err != nil {
		panic(err)
	}
	err = client.StartContainer(c.ID, &docker.HostConfig{
		Binds: []string{
			os.ExpandEnv("${PWD}/certs:/certs"),
		},
		PublishAllPorts: true,
	})
	if err != nil {
		panic(err)
	}
	log.Printf("created volumes")
	c.Name = "volumes"
	return c
}

func createRoach(client *docker.Client, vols *docker.Container,
	i int, cmd ...string) *docker.Container {
	var hostname string
	if i >= 0 {
		hostname = fmt.Sprintf("roach%d", i)
	}
	var entrypoint []string
	if *cockroachEntry != "" {
		entrypoint = append(entrypoint, *cockroachEntry)
	}
	c, err := client.CreateContainer(docker.CreateContainerOptions{
		Config: &docker.Config{
			Hostname:     hostname,
			Domainname:   domain,
			Image:        *cockroachImage,
			VolumesFrom:  vols.ID,
			ExposedPorts: map[docker.Port]struct{}{"8080/tcp": {}},
			Entrypoint:   entrypoint,
			Cmd:          cmd,
		}})
	if err != nil {
		panic(err)
	}
	return c
}

func createCACert(client *docker.Client, vols *docker.Container) {
	log.Printf("creating ca")
	c := createRoach(client, vols, -1,
		"cert", "--certs=/certs", "create-ca")
	defer remove(client, c)
	start(client, nil, c)
	wait(client, c)
}

func createNodeCerts(client *docker.Client, vols *docker.Container, numNodes int) {
	log.Printf("creating node certs: ./certs")
	var nodes []string
	for i := 0; i < numNodes; i++ {
		nodes = append(nodes, node(i))
	}
	c := createRoach(client, vols, -1,
		append([]string{"cert", "--certs=/certs", "create-node"}, nodes...)...)
	defer remove(client, c)
	start(client, nil, c)
	wait(client, c)
}

func initCluster(client *docker.Client, vols *docker.Container) {
	log.Printf("initializing cluster")
	c := createRoach(client, vols, -1,
		"init", "--stores=ssd="+data(0))
	defer remove(client, c)
	start(client, nil, c)
	wait(client, c)
}

func startNode(client *docker.Client, vols, dns *docker.Container,
	numNodes, i int) *docker.Container {
	cmd := []string{
		"start",
		"--stores=ssd=" + data(i),
		"--certs=/certs",
		"--addr=" + node(i) + ":8080",
		"--gossip=" + node(0) + ":8080",
	}
	c := createRoach(client, vols, i, cmd...)
	start(client, dns, c)
	c = inspect(client, c.ID)
	c.Name = node(i)
	ports := c.NetworkSettings.PortMappingAPI()
	log.Printf("started %s: %s:%d", c.Name, dockerIP(), ports[0].PublicPort)
	return c
}

func checkGossipNodes(client *http.Client, node *docker.Container) int {
	mappings := node.NetworkSettings.PortMappingAPI()
	addr := fmt.Sprintf("%s:%d", dockerIP(), mappings[0].PublicPort)

	resp, err := client.Get("https://" + addr + "/_status/gossip")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0
	}
	count := 0
	infos := m["infos"].(map[string]interface{})
	for k := range infos {
		if strings.HasPrefix(k, "node:") {
			count++
		}
	}
	return count
}

func checkCluster(nodes []*docker.Container, done chan struct{}) {
	defer func() {
		done <- struct{}{}
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}

	log.Printf("waiting for complete gossip network of %d peerings",
		len(nodes)*len(nodes))

	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		found := 0
		for j := 0; j < len(nodes); j++ {
			found += checkGossipNodes(client, nodes[j])
		}
		fmt.Printf("%d ", found)
		if found == len(nodes)*len(nodes) {
			fmt.Printf("... all nodes verified in the cluster\n")
			return
		}
	}

	fmt.Printf("... failed to verify all nodes in cluster\n")
}

func main() {
	log.SetFlags(log.Ltime)
	flag.Parse()

	client := newDockerClient()
	dns := runDockerSpy(client)
	defer kill(client, dns)
	log.Printf("started %s: %s\n", dns.Name, dns.NetworkSettings.IPAddress)

	vols := createVolumes(client, *numNodes)
	defer remove(client, vols)
	defer os.RemoveAll("certs")

	createCACert(client, vols)
	createNodeCerts(client, vols, *numNodes)
	initCluster(client, vols)

	var nodes []*docker.Container
	for i := 0; i < *numNodes; i++ {
		c := startNode(client, vols, dns, *numNodes, i)
		defer kill(client, c)
		nodes = append(nodes, c)
	}

	done := make(chan struct{}, 1)
	go checkCluster(nodes, done)
	if *waitInterrupt {
		done = nil
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	select {
	case <-c:
	case <-done:
	}
}

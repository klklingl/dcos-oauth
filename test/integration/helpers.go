package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"net"
	"errors"
)

type basicAuth struct {
	username string
	password string
}

func waitForPortAvailability(timeout time.Duration, port int) error {
	tm := time.After(timeout)
	ipAndPort := fmt.Sprint("127.0.0.1:", port)
	for {
		if conn, err := net.Dial("tcp", ipAndPort); err == nil {
			return conn.Close()
		}
		select {
		case <-tm:
			return errors.New("Connection to "+ipAndPort+" timed out")
		case <-time.After(100 * time.Millisecond):
			continue
		}
	}
}

func startZk() error {
	cmd := exec.Command("sudo", "docker", "run", "-d", "--net=host", "--name=dcos-zk", "jplock/zookeeper")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return waitForPortAvailability(10*time.Second, 2181)
}

func startOAuthAPI(additionalDockerArgs []string) error {
	secretKeyFile, err := ioutil.TempFile("", "dcos-oauth-integration-test")
	if err != nil {
		return err
	}
	defer os.Remove(secretKeyFile.Name())

	allArgs := append(
		[]string{
			"docker",
			"run",
			"-d",
			"-v="+secretKeyFile.Name()+":/var/lib/dcos/auth-token-secret",
			"--net=host",
			"--name=dcos-oauth",
		},
		additionalDockerArgs...)
	allArgs = append(allArgs,
			"dcos-services",
			"/go/bin/dcos-oauth",
			"serve")
	cmd := exec.Command("sudo", allArgs...)
	err = cmd.Run()
	if err != nil {
		return err
	}
	return waitForPortAvailability(10*time.Second, 8101)
}

func startConfigAPI() error {
	cmd := exec.Command("sudo", "docker", "run", "-d", "--net=host", "--name=dcos-config", "dcos-services", "/go/bin/dcos-config", "serve")
	err := cmd.Run()
	if err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func cleanup(service string) {
	cmd := exec.Command("sudo", "docker", "rm", "-f", service, "dcos-zk")
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func encodeData(data interface{}) (*bytes.Buffer, error) {
	params := bytes.NewBuffer(nil)
	if data != nil {
		if err := json.NewEncoder(params).Encode(data); err != nil {
			return nil, err
		}
	}
	return params, nil
}

func send(method, route string, statusExpected int, obj interface{}, bAuth *basicAuth) (string, error) {
	body, err := encodeData(obj)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(method, "http://127.0.0.1:8101"+route, body)
	if err != nil {
		return "", err
	}
	if bAuth != nil {
		req.SetBasicAuth(bAuth.username, bAuth.password)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != statusExpected {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("%s", body)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return strings.TrimSpace(string(respBody)), err
}

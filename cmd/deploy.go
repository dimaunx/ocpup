package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	secv1 "github.com/openshift/api/security/v1"
	scc "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"
)

var (
	DeployTool  string
	Reinstall   bool
	Update      bool
	HostNetwork bool
)

const submOperatorNsName = "openshift-submariner"
const submOperatorBrokerNsName = "submariner-k8s-broker"
const submBrokerSaName = "submariner-k8s-broker-client"

//Run helm init and add a submariner repository
func HelmInit(repo string) error {
	log.Infof("Running helm init...")
	cmdName := "./bin/helm"
	initArgs := []string{"init", "--client-only"}
	addArgs := []string{"repo", "add", "submariner-latest", repo}

	cmd1 := exec.Command(cmdName, initArgs...)
	cmd2 := exec.Command(cmdName, addArgs...)
	buf := &bytes.Buffer{}
	cmd1.Stdout = buf
	cmd1.Stderr = buf
	cmd2.Stdout = buf
	cmd2.Stderr = buf

	err := cmd1.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: \n%s", buf.String())
	}

	err = cmd1.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error waiting for helm: \n%s", buf.String())
	}

	err = cmd2.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: \n%s", buf.String())
	}

	err = cmd2.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error waiting for helm: \n%s", buf.String())
	}

	log.Debugf("Helm repo %s was added.", repo)
	return nil
}

//Generate Psk for submariner tunnels
func GeneratePsk() string {
	var letterRunes = []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 64)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Delete submariner helm deployment
func (cl *ClusterData) DeleteSubmarinerHelm(ns string) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/helm"
	cmdArgs := []string{"del", "--purge", ns, "--kubeconfig", kubeConfigFile, "--debug"}

	logFile := filepath.Join(currentDir, ".config", cl.ClusterName, ".openshift_install.log")
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer f.Close()
	buf := &bytes.Buffer{}
	mwriter := io.MultiWriter(f, buf)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	err = cmd.Run()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Submariner deployment in %s namespace was removed from %s.", ns, infraDetails[0])
	return nil
}

//Generate config files
func (cl *ClusterData) GenerateOperatorConfigs(config *ClustersConfig, broker *ClusterData, psk string) error {
	currentDir, _ := os.Getwd()
	configDir := filepath.Join(currentDir, ".config", cl.ClusterName)

	t, err := template.ParseFiles(filepath.Join(currentDir, "tpl/operator-group.yaml"))
	if err != nil {
		return err
	}

	groupFile := filepath.Join(configDir, cl.ClusterName+"-operator-group.yaml")
	f, err := os.Create(groupFile)
	if err != nil {
		return errors.Wrapf(err, "creating operator group config file %s", cl.ClusterName)
	}

	err = t.Execute(f, config.Operator)
	if err != nil {
		return errors.Wrapf(err, "creating operator group config file %s", cl.ClusterName)
	}

	if err := f.Close(); err != nil {
		return err
	}
	log.Debugf("Operator group config file for %s generated.", cl.ClusterName)

	t, err = template.ParseFiles(filepath.Join(currentDir, "tpl/submariner-cr.yaml"))
	if err != nil {
		return err
	}

	crFile := filepath.Join(configDir, cl.ClusterName+"-submariner-cr.yaml")
	f, err = os.Create(crFile)
	if err != nil {
		return errors.Wrapf(err, "creating submariner operator CR config file %s", cl.ClusterName)
	}

	var token string
	var ca string

	type crConfig struct {
		ClusterId   string
		IpsecPsk    string
		BrokerCa    string
		BrokerApi   string
		BrokerToken string
		ClusterData
		OperatorData
	}

	brokerInfraData, err := broker.ExtractInfraDetails()
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	brokerSecretData, err := broker.ExportBrokerSecretData(submOperatorBrokerNsName)
	if brokerSecretData == nil || err != nil {
		return errors.Wrapf(err, "Unable to get broker secret data from %s.", brokerInfraData[0])
	}

	for k, v := range brokerSecretData {
		if k == "token" {
			token = string(v)
		} else if k == "ca.crt" {
			ca = base64.StdEncoding.EncodeToString([]byte(string(v)))
		}
	}

	brokerUrl := []string{"api", brokerInfraData[2], broker.DNSDomain}

	err = t.Execute(f, crConfig{
		ClusterId:    infraDetails[0],
		IpsecPsk:     psk,
		BrokerCa:     ca,
		BrokerApi:    strings.Join(brokerUrl, ".") + ":6443",
		BrokerToken:  token,
		ClusterData:  *cl,
		OperatorData: config.Operator,
	})
	if err != nil {
		return errors.Wrapf(err, "creating submariner operator CR config file %s", cl.ClusterName)
	}

	if err := f.Close(); err != nil {
		return err
	}
	log.Debugf("Submariner operator CR config file for %s generated.", cl.ClusterName)
	return nil
}

// Delete submariner CRDs
func (cl *ClusterData) DeleteSubmarinerCrd() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/oc"
	cmdArgs := []string{
		"delete", "crd", "clusters.submariner.io", "endpoints.submariner.io", "submariners.submariner.io",
		"--config", kubeConfigFile}

	logFile := filepath.Join(currentDir, ".config", cl.ClusterName, ".openshift_install.log")
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	defer f.Close()
	buf := &bytes.Buffer{}
	mwriter := io.MultiWriter(f, buf)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	err = cmd.Run()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Submariner CRDs were removed from %s.", infraDetails[0])
	return nil
}

// Deploy submariner with operator
func (cl *ClusterData) DeploySubmarinerOperator(config *ClustersConfig, broker *ClusterData, psk string, wg *sync.WaitGroup) error {
	err := cl.DeployOperatorSource()
	if err != nil {
		return err
	}

	err = cl.CreateNameSpace(submOperatorNsName)
	if err != nil {
		return err
	}

	err = cl.AddSubmarinerSecurityContext(&config.Helm)
	if err != nil {
		return err
	}

	err = cl.GenerateOperatorConfigs(config, broker, psk)
	if err != nil {
		return err
	}

	err = cl.DeployOperatorGroup()
	if err != nil {
		return err
	}

	err = cl.WaitForOperatorDeployment(submOperatorNsName)
	if err != nil {
		return err
	}

	err = cl.DeployOperatorCr()
	if err != nil {
		return err
	}

	err = cl.WaitForSubmarinerDeployment(submOperatorNsName)
	if err != nil {
		return err
	}
	wg.Done()
	return nil
}

// Deploy operator source
func (cl *ClusterData) DeployOperatorSource() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", cl.ClusterName)
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	operatorSourceFile := filepath.Join(currentDir, "deploy/operator/operator-source.yaml")

	cmdName := "./bin/oc"
	cmdArgs := []string{"apply", "-f", operatorSourceFile, "--config", kubeConfigFile}
	buf := &bytes.Buffer{}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "Error deploying operator source: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Operator source was deployed to %s.", infraDetails[0])
	return nil
}

// Deploy broker rbac roles
func (cl *ClusterData) DeployBrokerRbac() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", cl.ClusterName)
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	brokerFile := filepath.Join(currentDir, "deploy/operator/broker-rbac.yaml")

	cmdName := "./bin/oc"
	cmdArgs := []string{"apply", "-f", brokerFile, "--config", kubeConfigFile}
	buf := &bytes.Buffer{}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Run()
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ Rbac rules for broker: %s already exists.", infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "Failed to rbac rules for %s.", infraDetails[0])
	} else {
		log.Infof("✔ Rbac rules were created for broker: %s.", infraDetails[0])
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	return nil
}

// Deploy operator source
func (cl *ClusterData) DeployOperatorGroup() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", cl.ClusterName)
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	operatorGroupFile := filepath.Join(currentDir, ".config", cl.ClusterName, cl.ClusterName+"-operator-group.yaml")

	cmdName := "./bin/oc"
	cmdArgs := []string{"apply", "-f", operatorGroupFile, "--config", kubeConfigFile}
	buf := &bytes.Buffer{}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "Error deploying operator group: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Operator group was deployed to %s.", infraDetails[0])
	return nil
}

// Deploy submariner CR
func (cl *ClusterData) DeployOperatorCr() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", cl.ClusterName)
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	operatorGroupFile := filepath.Join(currentDir, ".config", cl.ClusterName, cl.ClusterName+"-submariner-cr.yaml")

	cmdName := "./bin/oc"
	cmdArgs := []string{"apply", "-f", operatorGroupFile, "--config", kubeConfigFile}
	buf := &bytes.Buffer{}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "Error deploying operator config: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Operator config was deployed to %s.", infraDetails[0])
	return nil
}

// Update Engine deployment
func (cl *ClusterData) UpdateEngineDeployment(h *HelmData) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	log.Debugf("Updating engine deployment %s.", cl.ClusterName)
	deploymentsClient := clientset.AppsV1().Deployments(h.Engine.Namespace)

	result, err := deploymentsClient.Get("submariner", metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Failed to get latest version of submariner engine deployment: %s", cl.ClusterName)
	}

	image := h.Engine.Image.Repository + ":" + h.Engine.Image.Tag

	result.Spec.Template.Spec.Containers[0].Image = image
	_, err = deploymentsClient.Update(result)
	if err != nil {
		return errors.Wrapf(err, "Failed to update submariner engine deployment: %s", cl.ClusterName)
	}
	log.Infof("✔ Submariner engine deployment for %s was updated with image: %s.", cl.ClusterName, image)
	return nil
}

// Update route agent deployment
func (cl *ClusterData) UpdateRouteAgentDaemonSet(h *HelmData) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	log.Debugf("Updating route agent daemon set %s.", cl.ClusterName)
	dsClient := clientset.AppsV1().DaemonSets(h.RouteAgent.Namespace)

	result, err := dsClient.Get("submariner-routeagent", metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "Failed to get latest version of submariner route agent daemon set: %s", cl.ClusterName)
	}

	image := h.RouteAgent.Image.Repository + ":" + h.RouteAgent.Image.Tag

	result.Spec.Template.Spec.Containers[0].Image = image
	_, err = dsClient.Update(result)
	if err != nil {
		return errors.Wrapf(err, "Failed to update submariner route agent daemon set: %s", cl.ClusterName)
	}
	log.Infof("✔ Submariner route agent daemon set for %s was updated with image: %s.", cl.ClusterName, image)
	return nil
}

// Deploy netshoot pods
func (cl *ClusterData) DeployNetshootDaemonSet(wg *sync.WaitGroup) error {
	var dsFile string
	currentDir, _ := os.Getwd()

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrap(err, "error reading kubeconfig file")
	}

	if HostNetwork {
		dsFile = filepath.Join(currentDir, "deploy/debug/netshoot-ds-host.yaml")
	} else {
		dsFile = filepath.Join(currentDir, "deploy/debug/netshoot-ds.yaml")
	}

	log.Debugf("Deploying netshoot daemon set %s, host network: %v.", infraDetails[0], HostNetwork)

	file, err := ioutil.ReadFile(dsFile)
	if err != nil {
		return errors.Wrap(err, "Error loading the deployment file")
	}

	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(file, nil, nil)
	if err != nil {
		return err
	}

	_, err = clientset.AppsV1().DaemonSets("default").Create(obj.(*v1.DaemonSet))
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ %s %s", err.Error(), infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "Failed deploy netshoot daemon set %s", infraDetails[0])
	} else {
		log.Infof("✔ Netshoot daemon set for %s was deployed.", infraDetails[0])
	}
	wg.Done()
	return nil
}

// Deploy nginx-demo pods and service
func (cl ClusterData) DeployNginxDemo(wg *sync.WaitGroup) error {

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	nginxFile := filepath.Join(currentDir, "deploy/debug/nginx-demo.yaml")
	file, err := ioutil.ReadFile(nginxFile)
	if err != nil {
		return err
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	acceptedK8sTypes := regexp.MustCompile(`(Service|DaemonSet)`)
	fileAsString := string(file[:])
	sepYamlfiles := strings.Split(fileAsString, "---")
	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}

		decode := scheme.Codecs.UniversalDeserializer().Decode
		obj, groupVersionKind, err := decode([]byte(f), nil, nil)

		if err != nil {
			return errors.Wrap(err, "Error while decoding YAML object. Err was: ")
		}

		if !acceptedK8sTypes.MatchString(groupVersionKind.Kind) {
			log.Warnf("The file %s contains K8s object types which are not supported! Skipping object with type: %s", nginxFile, groupVersionKind.Kind)
		} else {
			switch o := obj.(type) {
			case *v1.DaemonSet:
				result, err := clientset.AppsV1().DaemonSets("default").Create(o)
				if err != nil && strings.Contains(err.Error(), "already exists") {
					log.Infof("✔ %s %s", err.Error(), infraDetails[0])
				} else if err != nil {
					return err
				} else {
					log.Infof("✔ nginx-demo daemon set was created for %s at: %s", infraDetails[0], result.CreationTimestamp)
				}
			case *corev1.Service:
				result, err := clientset.CoreV1().Services("default").Create(o)
				if err != nil && strings.Contains(err.Error(), "already exists") {
					log.Infof("✔ %s %s", err.Error(), infraDetails[0])
				} else if err != nil {
					return err
				} else {
					log.Infof("✔ nginx-demo service was created for %s at: %s", infraDetails[0], result.CreationTimestamp)
				}
			}
		}
	}
	wg.Done()
	return nil
}

//Export submariner broker ca and token
func (cl *ClusterData) ExportBrokerSecretData(ns string) (map[string][]byte, error) {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	saClient := clientset.CoreV1().Secrets(ns)

	saList, err := saClient.List(metav1.ListOptions{FieldSelector: "type=kubernetes.io/service-account-token"})
	if err == nil && len(saList.Items) > 0 {
		for _, sa := range saList.Items {
			if strings.Contains(sa.Name, "submariner-k8s-broker-client-token") {
				b := new(bytes.Buffer)
				for key, value := range sa.Annotations {
					_, _ = fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
				}
				if !strings.Contains(b.String(), "openshift.io") {
					log.Debugf("Getting data for %s %s", sa.Name, cl.ClusterName)
					return sa.Data, nil
				}
			}
		}
	} else {
		log.Errorf("Could not get broker token for %s", cl.ClusterName)
	}
	return nil, nil
}

//Install submariner broker
func (cl *ClusterData) InstallSubmarinerBrokerHelm(h *HelmData) error {

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", cl.ClusterName)
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/helm"
	cmdArgs := []string{
		"install", "--debug", "submariner-latest/submariner-k8s-broker",
		"--name", h.Broker.Namespace,
		"--namespace", h.Broker.Namespace,
		"--kubeconfig", kubeConfigFile,
	}

	logFile := filepath.Join(currentDir, ".config", cl.ClusterName, ".openshift_install.log")
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer f.Close()
	buf := &bytes.Buffer{}
	mwriter := io.MultiWriter(f, buf)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	err = cmd.Run()
	if err != nil && !strings.Contains(buf.String(), "already exists") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Broker was installed on %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)
	return nil
}

//Install submariner gateway
func (cl *ClusterData) InstallSubmarinerGatewayHelm(wg *sync.WaitGroup, broker *ClusterData, h *HelmData, psk string, ns string) error {
	var token string
	var ca string
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")

	brokerInfraData, err := broker.ExtractInfraDetails()
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	brokerSecretData, err := broker.ExportBrokerSecretData(h.Broker.Namespace)
	if brokerSecretData == nil || err != nil {
		return errors.New("Unable to get broker secret data.")
	}

	for k, v := range brokerSecretData {
		if k == "token" {
			token = string(v)
		} else if k == "ca.crt" {
			ca = base64.StdEncoding.EncodeToString([]byte(string(v)))
		}
	}

	log.Debugf("Installing gateway %s.", cl.ClusterName)
	brokerUrl := []string{"api", brokerInfraData[2], broker.DNSDomain}
	cmdName := "./bin/helm"
	setArgs := []string{
		"ipsec.psk=" + psk,
		"ipsec.ikePort=501",
		"ipsec.natPort=4501",
		"broker.server=" + strings.Join(brokerUrl, ".") + ":6443",
		"broker.token=" + token,
		"broker.namespace=" + h.Broker.Namespace,
		"broker.ca=" + ca,
		"submariner.clusterId=" + cl.ClusterName,
		"submariner.clusterCidr=" + cl.PodCidr,
		"submariner.serviceCidr=" + cl.SvcCidr,
		"submariner.natEnabled=true",
		"routeAgent.image.repository=" + h.RouteAgent.Image.Repository,
		"routeAgent.image.tag=" + h.RouteAgent.Image.Tag,
		"engine.image.repository=" + h.Engine.Image.Repository,
		"engine.image.tag=" + h.Engine.Image.Tag,
	}

	if cl.SubmarinerType == "broker" {
		setArgs = append(setArgs, "crd.create=false")
	}

	cmdArgs := []string{
		"install", "--debug", h.HelmRepo.Name + "/submariner",
		"--name", "submariner",
		"--namespace", h.Engine.Namespace,
		"--kubeconfig", kubeConfigFile,
		"--set", strings.Join(setArgs, ","),
	}

	logFile := filepath.Join(currentDir, ".config", cl.ClusterName, ".openshift_install.log")
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer f.Close()
	buf := &bytes.Buffer{}
	mwriter := io.MultiWriter(f, buf)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s\n%s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "already exists") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Gateway was installed on %s, type; %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)
	wg.Done()
	return nil
}

// Delete namespace
func (cl *ClusterData) DeleteNameSpace(ns string, t time.Duration) error {
	currentDir, _ := os.Getwd()

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "error reading kubeconfig file %s.", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "error using kubeconfig file %s.", infraDetails[0])
	}

	log.Debugf("Deleting namespace: %s for  %s.", ns, infraDetails[0])
	coreClient := clientset.CoreV1().Namespaces()

	deletePolicy := metav1.DeletePropagationBackground
	err = coreClient.Delete(ns, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil && strings.Contains(err.Error(), "not found") {
		log.Infof("✔ Namespace: %s for %s was deleted.", ns, infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "Failed to delete submariner namespace: %s for %s.", ns, infraDetails[0])
	} else {
		log.Infof("✔ Namespace: %s for %s was deleted.", ns, infraDetails[0])
	}

	log.Infof("✔ Waiting %v seconds for garbage collector to delete resources for %s ,namespace: %s.", t*time.Second, infraDetails[0], ns)
	time.Sleep(t * time.Second)
	return nil
}

// Create namespace
func (cl *ClusterData) CreateNameSpace(ns string) error {
	currentDir, _ := os.Getwd()

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "error reading kubeconfig file %s.", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "error using kubeconfig file %s.", infraDetails[0])
	}

	log.Debugf("Creating submariner namespace for  %s.", infraDetails[0])
	coreClient := clientset.CoreV1().Namespaces()

	nsSpec := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	_, err = coreClient.Create(nsSpec)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ Namespace: %s for %s already exists.", ns, infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "Failed to create submariner namespace: %s for %s.", ns, infraDetails[0])
	} else {
		log.Infof("✔ Namespace: %s for %s was created.", ns, infraDetails[0])
	}
	return nil
}

// Create sa
func (cl *ClusterData) CreateSa(ns string) error {
	currentDir, _ := os.Getwd()

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "error reading kubeconfig file %s.", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "error using kubeconfig file %s.", infraDetails[0])
	}

	log.Debugf("Creating broker service sccount for  %s.", infraDetails[0])
	coreClient := clientset.CoreV1().ServiceAccounts(ns)

	saSpec := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: submBrokerSaName}}
	_, err = coreClient.Create(saSpec)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ Service account: %s for %s already exists.", submBrokerSaName, infraDetails[0])
	} else if err != nil {
		return errors.Wrapf(err, "Failed to create service account: %s for %s.", submBrokerSaName, infraDetails[0])
	} else {
		log.Infof("✔ Service account: %s for %s was created.", submBrokerSaName, infraDetails[0])
	}
	return nil
}

//Add submariner security policy to gateway node
func (cl *ClusterData) AddSubmarinerSecurityContext(h *HelmData) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	clientset, err := scc.NewForConfig(config)
	if err != nil {
		return err
	}

	sc, err := clientset.SecurityContextConstraints().Get("privileged", metav1.GetOptions{})
	if err != nil {
		return err
	}

	sec := secv1.SecurityContextConstraints{}

	sc.DeepCopyInto(&sec)

	submUsers := []string{
		"system:serviceaccount:" + h.Engine.Namespace + ":submariner-routeagent",
		"system:serviceaccount:" + h.Engine.Namespace + ":submariner-engine",
		"system:serviceaccount:" + submOperatorNsName + ":submariner-operator",
	}

	usersToAdd, _ := diff(submUsers, sc.Users)

	sec.Users = append(sec.Users, usersToAdd...)

	_, err = clientset.SecurityContextConstraints().Update(&sec)
	if err != nil {
		return err
	}

	log.Infof("✔ Security context updated for %s.", infraDetails[0])
	return nil
}

//Wait for submariner engine deployment ro be ready
func (cl *ClusterData) WaitForSubmarinerDeployment(ns string) error {
	ctx := context.Background()
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	submarinerTimeout := 5 * time.Minute
	log.Infof("Waiting up to %v for submariner engine to be created for %s...", submarinerTimeout, infraDetails[0])
	submarinerContext, cancel := context.WithTimeout(ctx, submarinerTimeout)
	deploymentsClient := clientset.AppsV1().Deployments(ns)
	wait.Until(func() {
		deployments, err := deploymentsClient.List(metav1.ListOptions{LabelSelector: "app=submariner-engine"})
		if err == nil && len(deployments.Items) > 0 {
			for _, deploy := range deployments.Items {
				if deploy.Status.ReadyReplicas == int32(cl.NumGateways) {
					log.Infof("✔ Submariner engine successfully deployed to %s, ready replicas: %v", infraDetails[0], deploy.Status.ReadyReplicas)
					cancel()
				} else if deploy.Status.ReadyReplicas < int32(cl.NumGateways) {
					log.Infof("Still waiting for submariner engine deployment %s, ready replicas: %v", infraDetails[0], deploy.Status.ReadyReplicas)
				}
			}
		} else if err != nil {
			log.Infof("Still waiting for submariner engine deployment for %s %v", infraDetails[0], err)
		}
	}, 10*time.Second, submarinerContext.Done())
	err = submarinerContext.Err()
	if err != nil && err != context.Canceled {
		return errors.Wrapf(err, "Error waiting for submariner engine deployment %s.", infraDetails[0])
	}
	return nil
}

//Wait for submariner operator be ready
func (cl *ClusterData) WaitForOperatorDeployment(ns string) error {
	ctx := context.Background()
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	submarinerTimeout := 15 * time.Minute
	log.Infof("Waiting up to %v for submariner operator to be running for %s...", submarinerTimeout, infraDetails[0])
	submarinerContext, cancel := context.WithTimeout(ctx, submarinerTimeout)
	deploymentsClient := clientset.AppsV1().Deployments(ns)
	wait.Until(func() {
		deployments, err := deploymentsClient.List(metav1.ListOptions{FieldSelector: "metadata.name=submariner-operator"})
		if err == nil && len(deployments.Items) > 0 {
			for _, deploy := range deployments.Items {
				if deploy.Status.ReadyReplicas == 1 {
					log.Infof("✔ Submariner operator was successfully deployed to %s, ready replicas: %v", infraDetails[0], deploy.Status.ReadyReplicas)
					cancel()
				} else if deploy.Status.ReadyReplicas < 1 {
					log.Infof("Still waiting for submariner operator deployment %s, ready replicas: %v", infraDetails[0], deploy.Status.ReadyReplicas)
				}
			}
		} else if err != nil {
			log.Infof("Still waiting for submariner operator deployment for %s %v", infraDetails[0], err)
		}
	}, 10*time.Second, submarinerContext.Done())
	err = submarinerContext.Err()
	if err != nil && err != context.Canceled {
		return errors.Wrapf(err, "Error waiting for submariner operator deployment %s.", infraDetails[0])
	}
	return nil
}

var deploySubmarinerCmd = &cobra.Command{
	Use:   "submariner",
	Short: "Update submariner deployment",
	Run: func(cmd *cobra.Command, args []string) {

		if Debug {
			log.SetReportCaller(true)
			log.SetLevel(log.DebugLevel)
		}

		config, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var wg sync.WaitGroup
		var broker ClusterData
		for _, cl := range config.Clusters {
			switch cl.SubmarinerType {
			case "broker":
				broker = cl
			}
		}

		switch DeployTool {
		case "operator":
			if Reinstall {
				err = broker.DeleteNameSpace(submOperatorBrokerNsName, 0)
				if err != nil {
					log.Fatal(err)
				}

				for _, cl := range config.Clusters {
					err = cl.DeleteNameSpace(submOperatorNsName, 30)
					if err != nil {
						log.Fatal(err)
					}

					err = cl.DeleteSubmarinerCrd()
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}

		psk := GeneratePsk()

		err = broker.CreateNameSpace(submOperatorBrokerNsName)
		if err != nil {
			log.Fatal(err)
		}

		err = broker.CreateSa(submOperatorBrokerNsName)
		if err != nil {
			log.Fatal(err)
		}

		err = broker.DeployBrokerRbac()
		if err != nil {
			log.Fatal(err)
		}

		wg.Add(len(config.Clusters))
		for _, cl := range config.Clusters {
			go func(cl ClusterData) {
				err = cl.DeploySubmarinerOperator(&config, &broker, psk, &wg)
				if err != nil {
					defer wg.Done()
					log.Fatal(err)
				}
			}(cl)
		}
		wg.Wait()
	},
}

var deployNetshootCmd = &cobra.Command{
	Use:   "netshoot",
	Short: "Deploy debug netshoot pods to all clusters",
	Run: func(cmd *cobra.Command, args []string) {

		if Debug {
			log.SetReportCaller(true)
			log.SetLevel(log.DebugLevel)
		}

		config, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(len(config.Clusters))
		for _, cl := range config.Clusters {
			go func(cl ClusterData) {
				err = cl.DeployNetshootDaemonSet(&wg)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()
	},
}

var deployNginxDemoCmd = &cobra.Command{
	Use:   "nginx-demo",
	Short: "Deploy nginx-demo application to all clusters",
	Run: func(cmd *cobra.Command, args []string) {

		if Debug {
			log.SetReportCaller(true)
			log.SetLevel(log.DebugLevel)
		}

		config, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(len(config.Clusters))
		for _, cl := range config.Clusters {
			go func(cl ClusterData) {
				err = cl.DeployNginxDemo(&wg)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()
	},
}

func init() {
	var deployCmd = &cobra.Command{
		Use:   "deploy",
		Short: "deploy resources",
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			config, err := ParseConfigFile()
			if err != nil {
				log.Fatal(err)
			}

			err = ModifyKubeConfigFiles(config.Clusters)
			if err != nil {
				log.Error(err)
			}
		},
	}
	rootCmd.AddCommand(deployCmd)
	deployCmd.AddCommand(deploySubmarinerCmd)
	deployCmd.AddCommand(deployNetshootCmd)
	deployCmd.AddCommand(deployNginxDemoCmd)
	deploySubmarinerCmd.Flags().StringVarP(&DeployTool, "deploytool", "d", "operator", "deploy tool for submariner [operator,helm]")
	deploySubmarinerCmd.Flags().BoolVarP(&Reinstall, "reinstall", "", false, "full submariner reinstall")
	deployNetshootCmd.Flags().BoolVarP(&HostNetwork, "host-network", "", false, "deploy debug pods with host networking")
}

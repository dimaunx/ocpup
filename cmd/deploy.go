package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	secv1 "github.com/openshift/api/security/v1"
	scc "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	EngineImage     string
	RouteAgentImage string
	Reinstall       bool
	Update          bool
	HostNetwork     bool
)

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

// Delete submariner helm deployment
func (cl *ClusterData) DeleteSubmariner(ns string) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/helm"
	cmdArgs := []string{"del", "--purge", ns, "--kubeconfig", kubeConfigFile, "--debug"}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s\n%s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Submariner deployment in %s namespace was removed from %s.", ns, infraDetails[0])
	return nil
}

// Delete submariner CRDs
func (cl *ClusterData) DeleteSubmarinerCrd() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/oc"
	cmdArgs := []string{
		"delete", "crd", "clusters.submariner.io", "endpoints.submariner.io",
		"--config", kubeConfigFile}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s\n%s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Submariner CRDs were removed from %s.", infraDetails[0])
	return nil
}

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

	log.Debugf("Deploying netshoot daemon set %s, host network: %v.", cl.ClusterName, HostNetwork)

	file, err := ioutil.ReadFile(dsFile)
	if err != nil {
		return errors.Wrap(err, "error loading the deployment file")
	}

	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(file, nil, nil)
	if err != nil {
		return errors.New(err.Error())
	}

	_, err = clientset.AppsV1().DaemonSets("default").Create(obj.(*v1.DaemonSet))
	if err != nil && strings.Contains(err.Error(), "already exists") {
		log.Infof("✔ %s %s", err.Error(), cl.ClusterName)
	} else if err != nil {
		return errors.Wrapf(err, "Failed deploy netshoot daemon set %s", cl.ClusterName)
	} else {
		log.Infof("✔ Netshoot daemon set for %s was deployed.", cl.ClusterName)
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
	return nil
}

//Install submariner broker
func (cl *ClusterData) InstallSubmarinerBroker(h *HelmData) error {

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return err
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/helm"
	cmdArgs := []string{
		"install", "--debug", "submariner-latest/submariner-k8s-broker",
		"--name", h.Broker.Namespace,
		"--namespace", h.Broker.Namespace,
		"--kubeconfig", kubeConfigFile,
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

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
	log.Infof("✔ Broker was installed on %s.", infraDetails[0])
	return nil
}

//Install submariner gateway
func (cl *ClusterData) InstallSubmarinerGateway(wg *sync.WaitGroup, broker *ClusterData, h *HelmData, psk string) error {
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

	brokerSecretData, err := broker.ExportBrokerSecretData()
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

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s %s\n%s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "already exists") {
		return errors.Wrapf(err, "Error waiting for helm: %s %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Gateway was installed on %s, platform: %s.", infraDetails[0], cl.Platform.Name)
	wg.Done()
	return nil
}

//Add submariner security policy to gateway node
func (cl *ClusterData) AddSubmarinerSecurityContext(wg *sync.WaitGroup) error {
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
		"system:serviceaccount:submariner:submariner-routeagent",
		"system:serviceaccount:submariner:submariner-engine",
	}

	usersToAdd, _ := diff(submUsers, sc.Users)

	sec.Users = append(sec.Users, usersToAdd...)

	_, err = clientset.SecurityContextConstraints().Update(&sec)
	if err != nil {
		return err
	}

	log.Infof("✔ Security context updated for %s.", infraDetails[0])
	wg.Done()
	return nil
}

//Wait for submariner engine deployment ro be ready
func (cl *ClusterData) WaitForSubmarinerDeployment(wg *sync.WaitGroup, helm *HelmData) error {
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
	deploymentsClient := clientset.ExtensionsV1beta1().Deployments(helm.Engine.Namespace)
	wait.Until(func() {
		deployments, err := deploymentsClient.List(metav1.ListOptions{LabelSelector: "app=submariner-engine"})
		if err == nil && len(deployments.Items) > 0 {
			for _, deploy := range deployments.Items {
				if deploy.Status.ReadyReplicas == 1 {
					log.Infof("✔ Submariner engine successfully deployed to %s, ready replicas: %v", infraDetails[0], deploy.Status.ReadyReplicas)
					cancel()
				} else if deploy.Status.ReadyReplicas < 1 {
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
	wg.Done()
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

		clusters, _, helmConfig, openshiftConfig, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var brokercl ClusterData
		for _, cl := range clusters {
			switch cl.SubmarinerType {
			case "broker":
				brokercl = cl
			}
		}

		var wg sync.WaitGroup

		err = GetDependencies(&openshiftConfig)
		if err != nil {
			log.Fatal(err)
		}

		if EngineImage != "" {
			helmConfig.Engine.Image.Repository = strings.Split(EngineImage, ":")[0]
			helmConfig.Engine.Image.Tag = strings.Split(EngineImage, ":")[1]
		}

		if RouteAgentImage != "" {
			helmConfig.RouteAgent.Image.Repository = strings.Split(RouteAgentImage, ":")[0]
			helmConfig.RouteAgent.Image.Tag = strings.Split(RouteAgentImage, ":")[1]
		}

		if Reinstall {
			log.Warn("Reinstalling submariner.")
			err := brokercl.DeleteSubmariner(helmConfig.Broker.Namespace)
			if err != nil {
				log.Fatal(err)
			}

			for i := range clusters {
				err := clusters[i].DeleteSubmariner(helmConfig.Engine.Namespace)
				if err != nil {
					log.Fatal(err)
				}
				err = clusters[i].DeleteSubmarinerCrd()
				if err != nil {
					log.Fatal(err)
				}
			}
		}

		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.AddSubmarinerSecurityContext(&wg)
				if err != nil {
					defer wg.Done()
					log.Fatal(err)
				}
			}(cl)
		}
		wg.Wait()

		err = HelmInit(helmConfig.HelmRepo.URL)
		if err != nil {
			log.Fatal(err)
		}

		err = brokercl.InstallSubmarinerBroker(&helmConfig)
		if err != nil {
			log.Fatal(err)
		}

		psk := GeneratePsk()

		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.InstallSubmarinerGateway(&wg, &brokercl, &helmConfig, psk)
				if err != nil {
					defer wg.Done()
					log.Error(err)
				}
			}(cl)
		}
		wg.Wait()

		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.WaitForSubmarinerDeployment(&wg, &helmConfig)
				if err != nil {
					defer wg.Done()
					log.Error(err)
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

		clusters, _, _, _, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(len(clusters))
		for _, cl := range clusters {
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

		clusters, _, _, _, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(len(clusters))
		for _, cl := range clusters {
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
			clusters, _, _, _, err := ParseConfigFile()
			if err != nil {
				log.Fatal(err)
			}
			ModifyKubeConfigFiles(clusters)
		},
	}
	rootCmd.AddCommand(deployCmd)
	deployCmd.AddCommand(deploySubmarinerCmd)
	deployCmd.AddCommand(deployNetshootCmd)
	deployCmd.AddCommand(deployNginxDemoCmd)
	deploySubmarinerCmd.Flags().StringVarP(&EngineImage, "engine", "", "", "engine image:tag, should be used with --reinstall")
	deploySubmarinerCmd.Flags().StringVarP(&RouteAgentImage, "routeagent", "", "", "route agent image:tag, should be used with --reinstall")
	deploySubmarinerCmd.Flags().BoolVarP(&Reinstall, "reinstall", "", false, "full submariner reinstall")
	deployNetshootCmd.Flags().BoolVarP(&HostNetwork, "host-network", "", false, "deploy debug pods with host networking")
}

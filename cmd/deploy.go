package cmd

import (
	"bytes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	EngineImage     string
	RouteAgentImage string
	Reinstall       bool
	HostNetwork     bool
)

func (cl *ClusterData) DeleteSubmariner(ns string) error {
	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	cmdName := "./bin/helm"
	cmdArgs := []string{"del", "--purge", ns, "--kubeconfig", kubeConfigFile, "--debug"}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err := cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s\n%s", cl.ClusterName, buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", cl.ClusterName, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", cl.ClusterName, buf.String())
	log.Infof("✔ Submariner was removed from %s.", cl.ClusterName)
	return nil
}

func (cl *ClusterData) DeleteSubmarinerCrd() error {
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

	err := cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting helm: %s\n%s", cl.ClusterName, buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "not found") {
		return errors.Wrapf(err, "Error waiting for helm: %s\n%s", cl.ClusterName, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", cl.ClusterName, buf.String())
	log.Infof("✔ Submariner CRDs were removed from %s.", cl.ClusterName)
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

		var wg sync.WaitGroup

		GetDependencies(&openshiftConfig)

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
			err := clusters[0].DeleteSubmariner(helmConfig.Broker.Namespace)
			if err != nil {
				log.Error(err)
			}

			err = clusters[0].DeleteSubmarinerCrd()
			if err != nil {
				log.Error(err)
			}

			for i := 1; i <= len(clusters[1:]); i++ {
				err := clusters[i].DeleteSubmariner(helmConfig.Engine.Namespace)
				if err != nil {
					log.Error(err)
				}
				err = clusters[i].DeleteSubmarinerCrd()
				if err != nil {
					log.Error(err)
				}
			}

			HelmInit(helmConfig.HelmRepo.URL)
			clusters[0].InstallSubmarinerBroker(&helmConfig)

			psk := GeneratePsk()

			wg.Add(len(clusters[1:]))
			for i := 1; i <= len(clusters[1:]); i++ {
				go clusters[i].InstallSubmarinerGateway(&wg, &clusters[0], &helmConfig, psk)
			}
			wg.Wait()

			wg.Add(len(clusters[1:]))
			for i := 1; i <= len(clusters[1:]); i++ {
				go clusters[i].WaitForSubmarinerDeployment(&wg, &helmConfig)
			}
			wg.Wait()
		} else {
			for i := 1; i <= len(clusters[1:]); i++ {
				err := clusters[i].UpdateEngineDeployment(&helmConfig)
				if err != nil {
					log.Error(err)
				}
				err = clusters[i].UpdateRouteAgentDaemonSet(&helmConfig)
				if err != nil {
					log.Error(err)
				}
			}
		}
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
					log.Error(err)
					wg.Done()
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
	deploySubmarinerCmd.Flags().StringVarP(&EngineImage, "engine", "", "", "engine image:tag")
	deploySubmarinerCmd.Flags().StringVarP(&RouteAgentImage, "routeagent", "", "", "route agent image:tag")
	deploySubmarinerCmd.Flags().BoolVarP(&Reinstall, "reinstall", "", false, "full submariner reinstall")
	deployNetshootCmd.Flags().BoolVarP(&HostNetwork, "host-network", "", false, "deploy debug pods with host networking")
}

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/dustin/go-humanize"
	"github.com/mholt/archiver"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

var Username string

type KubeConfig struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

type ClusterData struct {
	ClusterName    string `yaml:"clusterName"`
	SubmarinerType string `yaml:"submarinerType"`
	ClusterType    string `yaml:"clusterType"`
	VpcCidr        string `yaml:"vpcCidr"`
	PodCidr        string `yaml:"podCidr"`
	SvcCidr        string `yaml:"svcCidr"`
	NumMasters     int    `yaml:"numMasters"`
	NumWorkers     int    `yaml:"numWorkers"`
	NumGateways    int    `yaml:"numGateways"`
	DNSDomain      string `yaml:"dnsDomain"`
	Platform       struct {
		Name            string `yaml:"name"`
		Region          string `yaml:"region"`
		LbFloatingIP    string `yaml:"lbFloatingIP"`
		ExternalNetwork string `yaml:"externalNetwork,omitempty"`
		ComputeFlavor   string `yaml:"computeFlavor,omitempty"`
	} `yaml:"platform"`
}

type ClustersConfig struct {
	Clusters []ClusterData
}

type HelmData struct {
	HelmRepo struct {
		URL  string `yaml:"url"`
		Name string `yaml:"name"`
	} `yaml:"helmRepo"`
	Broker struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"broker"`
	Engine struct {
		Namespace string `yaml:"namespace"`
		Image     struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"image"`
	} `yaml:"engine"`
	RouteAgent struct {
		Namespace string `yaml:"namespace"`
		Image     struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"image"`
	} `yaml:"routeAgent"`
}

type AuthData struct {
	PullSecret string `yaml:"pullSecret"`
	SSHKey     string `yaml:"sshKey"`
	OpenStack  struct {
		AuthURL        string `yaml:"authUrl"`
		Username       string `yaml:"userName"`
		Password       string `yaml:"password"`
		ProjectID      string `yaml:"projectId"`
		ProjectName    string `yaml:"projectName"`
		UserDomainName string `yaml:"userDomainName"`
	} `yaml:"openstack"`
}

type OpenshiftData struct {
	Version string `yaml:"version"`
}

type WriteCounter struct {
	Total    uint64
	FileName string
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc WriteCounter) PrintProgress() {
	// Clear the line by using a character return to go back to the start and remove
	// the remaining characters by filling it with spaces
	fmt.Printf("\r%s", strings.Repeat(" ", 180))

	// Return again and print current status of download
	// We use the humanize package to print the bytes in a meaningful way (e.g. 10 MB)
	fmt.Printf("\rDownloading %s... %s complete", wc.FileName, humanize.Bytes(wc.Total))
}

func diff(lhsSlice, rhsSlice []string) (lhsOnly []string, rhsOnly []string) {
	return singleDiff(lhsSlice, rhsSlice), singleDiff(rhsSlice, lhsSlice)
}

func singleDiff(lhsSlice, rhsSlice []string) (lhsOnly []string) {
	for _, lhs := range lhsSlice {
		found := false
		for _, rhs := range rhsSlice {
			if lhs == rhs {
				found = true
				break
			}
		}

		if !found {
			lhsOnly = append(lhsOnly, lhs)
		}
	}

	return lhsOnly
}

//Download tools
func DownloadFile(url string, filepath string, filename string) error {

	// Create the file, but give it a tmp file extension, this means we won't overwrite a
	// file until it's downloaded, but we'll remove the tmp extension once downloaded.
	out, err := os.Create(filepath + ".tmp")
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create our progress reporter and pass it to be used alongside our writer
	counter := &WriteCounter{FileName: filename}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	if err != nil {
		return err
	}

	// The progress use the same line so print a new line once it's finished downloading
	fmt.Print("\n")

	err = os.Rename(filepath+".tmp", filepath)
	if err != nil {
		return err
	}

	return nil
}

//Run terraform init
func TerraformInit() error {
	log.Info("Running Terraform init...")
	cmd := exec.Command("./bin/terraform", "init")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err := cmd.Run()
	if err != nil {
		return errors.Wrapf(err, "Error waiting for terraform init: \n%s", buf.String())
	}
	log.Debug(buf.String())
	return nil
}

//Get dependencies required for multi cluster setup
func GetDependencies(v *OpenshiftData) error {
	if runtime.GOOS == "linux" {
		log.Debugf("Hello from linux.")
	}

	shortVersion := strings.Split(v.Version, "-")[0]
	release := strings.Join(strings.Split(strings.Split(v.Version, "-")[0], ".")[:2], ".")
	log.Infof("Getting required tools OCP version: %s, release: %s.", v.Version, release)

	currentDir, _ := os.Getwd()
	binDir := filepath.Join(currentDir, "bin")
	tmpDir := filepath.Join(currentDir, "tmp")
	_ = os.MkdirAll(binDir, os.ModePerm)
	_ = os.MkdirAll(tmpDir, os.ModePerm)

	if _, err := os.Stat("./bin/helm"); os.IsNotExist(err) {
		err = DownloadFile("https://storage.googleapis.com/kubernetes-helm/helm-v2.14.1-linux-amd64.tar.gz", "./tmp/helm.tar.gz", "helm")
		if err != nil {
			return err
		}
		_ = os.Remove("./tmp/linux-amd64")
		err = archiver.Extract("./tmp/helm.tar.gz", "linux-amd64/helm", "./tmp")
		if err != nil {
			return err
		}

		oldLocation := "./tmp/linux-amd64/helm"
		newLocation := "./bin/helm"
		err = os.Rename(oldLocation, newLocation)
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Helm already exists.")
	}

	if _, err := os.Stat("./bin/terraform"); os.IsNotExist(err) {
		err = DownloadFile("https://releases.hashicorp.com/terraform/0.12.12/terraform_0.12.12_linux_amd64.zip", "./tmp/terraform.zip", "terraform")
		if err != nil {
			return err
		}

		z := archiver.Zip{
			ImplicitTopLevelFolder: false,
			OverwriteExisting:      true,
			MkdirAll:               false,
		}

		err = z.Extract("./tmp/terraform.zip", "terraform", "./bin")
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Terraform exists.")
	}

	if _, err := os.Stat("./bin/openshift-install"); os.IsNotExist(err) {
		err := GetOcpTools(v.Version)
		if err != nil {
			return err
		}
	} else {
		cmdName := "./bin/openshift-install"
		cmdArgs := []string{"version"}

		cmd := exec.Command(cmdName, cmdArgs...)
		buf := &bytes.Buffer{}
		cmd.Stdout = buf
		cmd.Stderr = buf

		err := cmd.Start()
		if err != nil {
			return errors.Wrapf(err, "Error starting openshift-install: \n%s", buf.String())
		}

		err = cmd.Wait()
		if err != nil {
			return errors.Wrapf(err, "Error waiting openshift-install: \n%s", buf.String())
		}

		if strings.Contains(buf.String(), shortVersion) {
			log.Debugf("OCP tools with version %s already exist.", shortVersion)
		} else {
			err := GetOcpTools(v.Version)
			if err != nil {
				return err
			}
		}
	}
	_ = os.RemoveAll(filepath.Join(currentDir, "tmp"))
	return nil
}

//Get openshift install and client binaries
func GetOcpTools(version string) error {
	url := "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/" + version + "/openshift-install-linux-" + version + ".tar.gz"
	err := DownloadFile(url, "./tmp/openshift-install-linux-"+version+".tar.gz", "openshift-install")
	if err != nil {
		return err
	}

	_ = os.Remove("./bin/openshift-install")
	source := "./tmp/openshift-install-linux-" + version + ".tar.gz"
	err = archiver.Extract(source, "openshift-install", "./bin")
	if err != nil {
		return err
	}

	url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/" + version + "/openshift-client-linux-" + version + ".tar.gz"
	err = DownloadFile(url, "./tmp/openshift-client-linux-"+version+".tar.gz", "oc")
	if err != nil {
		return err
	}

	_ = os.Remove("./bin/oc")
	source = "./tmp/openshift-client-linux-" + version + ".tar.gz"
	err = archiver.Extract(source, "oc", "./bin")
	if err != nil {
		return err
	}
	return nil
}

//Copy existing kubeconfig files with required changes
func ModifyKubeConfigFiles(cls []ClusterData) error {
	log.Info("Modifying kubeconfig files.")

	var kubeconf KubeConfig

	for _, cl := range cls {
		currentDir, _ := os.Getwd()
		kubeFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
		newKubeFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig-dev")
		kubefile, err := ioutil.ReadFile(kubeFile)
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(kubefile, &kubeconf)
		if err != nil {
			return err
		}

		kubeconf.CurrentContext = cl.ClusterName
		kubeconf.Contexts[0].Name = cl.ClusterName
		kubeconf.Contexts[0].Context.Cluster = cl.ClusterName
		kubeconf.Contexts[0].Context.User = cl.ClusterName
		kubeconf.Clusters[0].Name = cl.ClusterName
		kubeconf.Users[0].Name = cl.ClusterName

		d, err := yaml.Marshal(&kubeconf)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(newKubeFile, d, 0644)
		if err != nil {
			return err
		}
		log.Debugf("Modifying %s", kubeFile)
	}
	log.Infof("✔ Kubeconfigs: export KUBECONFIG=$(echo $(git rev-parse --show-toplevel)/.config/cl{1..%v}/auth/kubeconfig-dev | sed 's/ /:/g')", len(cls))
	return nil
}

//Generate config files
func GenerateConfigs(cl ClusterData, auth *AuthData) error {
	currentDir, _ := os.Getwd()

	configDir := filepath.Join(currentDir, ".config", cl.ClusterName)
	err := os.MkdirAll(configDir, os.ModePerm)
	if err != nil {
		return errors.Wrapf(err, "error creating config dir %s", cl.ClusterName)
	}

	log.Debugf("ClustersConfig directories for %s created.", cl.ClusterName)

	c, err := user.Current()
	if err != nil {
		return err
	}

	t, err := template.ParseFiles(filepath.Join(currentDir, "tpl", "install-config.yaml"))
	if err != nil {
		return err
	}

	tc, err := template.ParseFiles(filepath.Join(currentDir, "tpl", "clouds.yaml"))
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(currentDir, ".config", cl.ClusterName, "metadata.json")); os.IsNotExist(err) {
		configFile := filepath.Join(currentDir, ".config", cl.ClusterName, "install-config.yaml")
		f, err := os.Create(configFile)
		if err != nil {
			return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
		}

		type combined struct {
			ClusterData
			AuthData
		}

		switch cl.Platform.Name {
		case "openstack":
			cloudsFile := filepath.Join(currentDir, "clouds.yaml")
			cf, err := os.Create(cloudsFile)
			if err != nil {
				return errors.Wrapf(err, "creating clouds.yaml file %s", cl.ClusterName)
			}

			err = tc.Execute(cf, combined{cl, *auth})
			if err != nil {
				return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
			}

			if err := cf.Close(); err != nil {
				return err
			}

			cl.Platform.LbFloatingIP, err = cl.CreateApiDnsRecordsOsp(auth)
			if err != nil {
				return err
			}
		}

		if Username != "" {
			cl.ClusterName = Username + "-" + cl.ClusterName
		} else {
			cl.ClusterName = c.Username + "-" + cl.ClusterName
		}

		err = t.Execute(f, combined{cl, *auth})
		if err != nil {
			return errors.Wrapf(err, "creating config file %s", cl.ClusterName)
		}

		if err := f.Close(); err != nil {
			return err
		}

		log.Debugf("ClustersConfig files for %s generated.", cl.ClusterName)
	} else {
		log.Infof("metadata.json file exists for %s, skipping install config creation.", cl.ClusterName)
	}
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

//Parse the main config file
func ParseConfigFile() ([]ClusterData, AuthData, HelmData, OpenshiftData, error) {

	var config ClustersConfig
	var cls []ClusterData

	err := viper.ReadInConfig()
	if err != nil {
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, errors.Wrapf(err, "Unable to read config")
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, errors.Wrapf(err, "Unable to unmarshal config")
	}

	cls = append(cls, config.Clusters...)

	var auth AuthData
	err = viper.UnmarshalKey("authentication", &auth)
	if err != nil {
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}

	var helm HelmData
	err = viper.UnmarshalKey("helm", &helm)
	if err != nil {
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}

	var openshift OpenshiftData
	err = viper.UnmarshalKey("openshift", &openshift)
	if err != nil {
		return nil, AuthData{}, HelmData{}, OpenshiftData{}, err
	}
	return cls, auth, helm, openshift, nil
}

func (cl *ClusterData) WaitForPublicGatewayNodesAws() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	log.Infof("Waiting up to for submariner gateway nodes to be running on AWS for %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)

	sess, err := session.NewSession(&aws.Config{Region: aws.String(cl.Platform.Region)})
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	ec2svc := ec2.New(sess)

	vpcInput := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:kubernetes.io/cluster/" + infraDetails[0]),
				Values: []*string{aws.String("owned")},
			},
		},
	}

	vpcResult, err := ec2svc.DescribeVpcs(vpcInput)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	ec2Input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(*vpcResult.Vpcs[0].VpcId)},
			},
			{
				Name:   aws.String("tag:kubernetes.io/cluster/" + infraDetails[0]),
				Values: []*string{aws.String("owned")},
			},
			{
				Name:   aws.String("tag:submariner.io"),
				Values: []*string{aws.String("gateway")},
			},
		},
	}

	err = ec2svc.WaitUntilInstanceExists(ec2Input)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	ec2Result, err := ec2svc.DescribeInstances(ec2Input)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	for _, res := range ec2Result.Reservations {
		for _, instance := range res.Instances {
			err = ec2svc.WaitUntilInstanceStatusOk(&ec2.DescribeInstanceStatusInput{
				InstanceIds: []*string{aws.String(*instance.InstanceId)},
			})
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}
			log.Debugf("✔ Submariner gateway node %s AWS status is ok %s.", *instance.InstanceId, infraDetails[0])

			ctx := context.Background()
			currentDir, _ := os.Getwd()
			kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
			config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

			submarinerTimeout := 5 * time.Minute
			log.Infof("Waiting up to %v for submariner gateway node to join the cluster %s...", submarinerTimeout, infraDetails[0])
			gwNodeContext, cancel := context.WithTimeout(ctx, submarinerTimeout)
			nodesClient := clientset.CoreV1().Nodes()
			wait.Until(func() {
				node, err := nodesClient.Get(*instance.PrivateDnsName, metav1.GetOptions{})
				if err == nil {
					for _, status := range node.Status.Conditions {
						if status.Type == "Ready" {
							if status.Status == "True" {
								log.Infof("✔ Submariner gateway node %s is ready for %s.", *instance.PrivateDnsName, infraDetails[0])
								cancel()
							} else {
								log.Infof("Still waiting for submariner gateway node %s to be ready for %s.", *instance.PrivateDnsName, infraDetails[0])
							}
						}
					}
				} else {
					log.Infof("Still waiting for submariner gateway node %s to be ready for %s.", *instance.PrivateDnsName, infraDetails[0])
				}
			}, 10*time.Second, gwNodeContext.Done())
			err = gwNodeContext.Err()
			if err != nil && err != context.Canceled {
				return errors.Wrapf(err, "Error waiting for submariner node %s to be ready %s", *instance.PrivateDnsName, infraDetails[0])
			}
		}
	}
	return nil
}

//Label private cluster gateway nodes as submariner gateway
func (cl *ClusterData) PreparePrivateCluster() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	nodes, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/worker=",
	})
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	for i := 1; i <= cl.NumGateways; i++ {
		err = cl.LabelPrivateGatewayNode(nodes.Items[i].Name)
		if err != nil {
			return errors.Wrapf(err, "%s", infraDetails[0])
		}
	}

	if cl.Platform.Name == "aws" {
		sess, err := session.NewSession(&aws.Config{Region: aws.String(cl.Platform.Region)})
		if err != nil {
			return errors.Wrapf(err, "%s", infraDetails[0])
		}

		ec2svc := ec2.New(sess)

		vpcInput := &ec2.DescribeVpcsInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String("tag:kubernetes.io/cluster/" + infraDetails[0]),
					Values: []*string{aws.String("owned")},
				},
			},
		}

		vpcResult, err := ec2svc.DescribeVpcs(vpcInput)
		if err != nil {
			return errors.Wrapf(err, "%s", infraDetails[0])
		}

		secInput := &ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []*string{aws.String(*vpcResult.Vpcs[0].VpcId)},
				},
				{
					Name:   aws.String("tag:kubernetes.io/cluster/" + infraDetails[0]),
					Values: []*string{aws.String("owned")},
				},
				{
					Name:   aws.String("tag:Name"),
					Values: []*string{aws.String(infraDetails[0] + "-worker-sg")},
				},
			},
		}

		secResult, err := ec2svc.DescribeSecurityGroups(secInput)
		if err != nil {
			return errors.Wrapf(err, "%s", infraDetails[0])
		}

		if len(secResult.SecurityGroups) > 0 {
			for _, secgroup := range secResult.SecurityGroups {
				log.Infof("Creating VxLan security group rule for %s, type: %s, platform %s, worker sg: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name, *secgroup.GroupId)
				ruleInput := &ec2.AuthorizeSecurityGroupIngressInput{
					GroupId: aws.String(*secgroup.GroupId),
					IpPermissions: []*ec2.IpPermission{
						{
							FromPort:   aws.Int64(4800),
							IpProtocol: aws.String("udp"),
							ToPort:     aws.Int64(4800),
							UserIdGroupPairs: []*ec2.UserIdGroupPair{
								{
									Description: aws.String("Vxlan traffic for submariner"),
									GroupId:     aws.String(*secgroup.GroupId),
								},
							},
						},
					},
				}

				_, err = ec2svc.AuthorizeSecurityGroupIngress(ruleInput)
				if err != nil && strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
					log.Infof("VxLan security group rule already exist for %s, type: %s, platform %s, worker sg: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name, *secgroup.GroupId)
				} else if err != nil {
					return errors.Wrapf(err, "%s", infraDetails[0])
				}
			}
		} else {
			return errors.Errorf("Worker security group not found for %s, platform: %s, type: %s.", infraDetails[0], cl.Platform.Name, cl.ClusterType)
		}
	}
	return nil
}

func (cl *ClusterData) LabelPrivateGatewayNode(gw string) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	currentDir, _ := os.Getwd()
	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	node, err := clientset.CoreV1().Nodes().Get(gw, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	node.Labels["submariner.io/gateway"] = "true"
	_, err = clientset.CoreV1().Nodes().Update(node)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	log.Infof("✔ Node %s was labeled as a gateway node %s.", node.Name, infraDetails[0])
	return nil
}

//Extract infra details from metadata.json
func (cl *ClusterData) ExtractInfraDetails() ([]string, error) {
	currentDir, _ := os.Getwd()
	metaJson := filepath.Join(currentDir, ".config", cl.ClusterName, "metadata.json")
	jsonFile, err := os.Open(metaJson)
	if err != nil {
		return nil, err
	}

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(byteValue, &result)
	if err != nil {
		return nil, err
	}

	infraDetails := []string{result["infraID"].(string), result["clusterID"].(string), result["clusterName"].(string)}
	return infraDetails, nil
}

// Create OCP4 cluster using IPI
func (cl *ClusterData) CreateOcpCluster(v *OpenshiftData, auth *AuthData, wg *sync.WaitGroup) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}

	configDir := filepath.Join(currentDir, ".config", cl.ClusterName)
	log.Infof("Creating cluster %s type: %s, platform: %s. Detailed log: %s", cl.ClusterName, cl.ClusterType, cl.Platform.Name, configDir+"/.openshift_install.log")
	cmdName := "./bin/openshift-install"
	cmdArgs := []string{"create", "cluster", "--dir", configDir, "--log-level", "debug"}

	cmd := exec.Command(cmdName, cmdArgs...)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Run()
	if err != nil && strings.Contains(buf.String(), "already exists") {
		log.Debugf("✔ %s %s", err.Error(), cl.ClusterName)
	} else if err != nil {
		return errors.Wrapf(err, "Error waiting for installation completion: %s platform: %s. Detailed log: %s", cl.ClusterName, cl.Platform.Name, configDir+"/.openshift_install.log")
	}

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())

	log.Infof("✔ Openshift was installed on %s platform: %s, type: %s, clusterID: %s.", cl.ClusterName, cl.Platform.Name, cl.ClusterType, infraDetails[0])

	switch cl.Platform.Name {
	case "aws":
		if cl.ClusterType == "public" {

			err = cl.CreatePublicIpiResourcesAws()
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

			err = cl.DeployPublicMachineSetConfigAws()
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

			err = cl.WaitForPublicGatewayNodesAws()
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

		} else {
			err = cl.PreparePrivateCluster()
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}
		}
	case "openstack":
		if cl.ClusterType == "public" {
			return errors.New("Public openstack clusters are not supported!")
		} else {
			err = cl.PreparePrivateCluster()
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}

			err = cl.CreateAppsDnsRecordsOsp(auth)
			if err != nil {
				return errors.Wrapf(err, "%s", infraDetails[0])
			}
		}
	}

	err = cl.CreateTillerDeployment()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}
	wg.Done()
	return nil
}

//Run api dns creation terraform osp module
func (cl *ClusterData) CreateApiDnsRecordsOsp(a *AuthData) (string, error) {
	c, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	var infraId string
	if Username != "" {
		infraId = Username + "-" + cl.ClusterName
	} else {
		infraId = c.Username + "-" + cl.ClusterName
	}

	log.Infof("Creating api DNS records for %s type: %s, platform: %s.", cl.ClusterName, cl.ClusterType, cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-osp-dns",
		"-var", "infra_id=" + infraId,
		"-var", "dns_domain=" + cl.DNSDomain,
		"-var", "public_network_name=" + cl.Platform.ExternalNetwork,
		"-var", "osp_auth_url=" + a.OpenStack.AuthURL,
		"-var", "osp_user_name=" + a.OpenStack.Username,
		"-var", "osp_user_password=" + a.OpenStack.Password,
		"-var", "osp_user_domain_name=" + a.OpenStack.UserDomainName,
		"-var", "osp_tenant_id=" + a.OpenStack.ProjectID,
		"-var", "osp_tenant_name=" + a.OpenStack.ProjectName,
		"-var", "osp_region=" + cl.Platform.Region,
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-osp-dns.tfstate",
		"-auto-approve",
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return "", errors.Wrapf(err, "%s", cl.ClusterName)
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
	if err != nil {
		return "", errors.Wrapf(err, "Error waiting for dns records creation: %s\n %s", cl.ClusterName, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": cl.ClusterName,
	}).Debugf("%s %s", cl.ClusterName, buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ DNS records were created for %s. %s", cl.ClusterName, output[len(output)-2])

	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	var re = regexp.MustCompile(ansi)
	return re.ReplaceAllString(strings.Split(output[len(output)-2], " = ")[1], ""), nil
}

//Run apps dns creation terraform osp module
func (cl *ClusterData) CreateAppsDnsRecordsOsp(a *AuthData) error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	log.Infof("Creating vxlan security group rules and apps DNS records for %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-osp-sg",
		"-var", "infra_id=" + infraDetails[0],
		"-var", "dns_domain=" + cl.DNSDomain,
		"-var", "osp_auth_url=" + a.OpenStack.AuthURL,
		"-var", "osp_user_name=" + a.OpenStack.Username,
		"-var", "osp_user_password=" + a.OpenStack.Password,
		"-var", "osp_user_domain_name=" + a.OpenStack.UserDomainName,
		"-var", "osp_tenant_id=" + a.OpenStack.ProjectID,
		"-var", "osp_tenant_name=" + a.OpenStack.ProjectName,
		"-var", "osp_region=" + cl.Platform.Region,
		"-var", "public_network_name=" + cl.Platform.ExternalNetwork,
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-osp-sg.tfstate",
		"-auto-approve",
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
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
	if err != nil {
		return errors.Wrapf(err, "Error waiting for security group rules creation: %s\n %s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ Security group rules and DNS records were created for %s. %s", infraDetails[0], output[len(output)-2])
	return nil
}

// Deploy MachineSet config for submariner gateway nodes
func (cl *ClusterData) DeployPublicMachineSetConfigAws() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	machineSetConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, infraDetails[0]+"-submariner-gw-machine-set.yaml")
	cmdName := "./bin/oc"
	cmdArgs := []string{
		"apply", "-f", machineSetConfigFile, "--kubeconfig", kubeConfigFile,
	}

	logFile := filepath.Join(currentDir, ".config", cl.ClusterName, ".openshift_install.log")
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return errors.Wrapf(err, "Error opening file: ")
	}

	defer f.Close()
	buf := &bytes.Buffer{}
	mwriter := io.MultiWriter(f, buf)

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	err = cmd.Start()
	if err != nil {
		return errors.Wrapf(err, "Error starting oc: %s\n%s", infraDetails[0], buf.String())
	}

	err = cmd.Wait()
	if err != nil && !strings.Contains(buf.String(), "already exists") {
		return errors.Wrapf(err, "Error waiting for oc: %s\n%s", infraDetails[0], buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())
	log.Infof("✔ Submariner gateway MachineSet was deployed to %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)
	return nil
}

// Modify AWS IPI infrastructure
func (cl *ClusterData) CreatePublicIpiResourcesAws() error {

	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	log.Infof("Applying AWS IPI modifications for %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)
	cmdName := "./bin/terraform"
	cmdArgs := []string{
		"apply", "-target", "module." + cl.ClusterName + "-aws-ipi",
		"-var", "infra_id=" + infraDetails[0],
		"-var", "aws_region=" + cl.Platform.Region,
		"-var", "num_gateways=" + strconv.Itoa(cl.NumGateways),
		"-state", "tf/state/" + "terraform-" + cl.ClusterName + "-aws-ipi.tfstate",
		"-auto-approve",
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
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
		return errors.Wrapf(err, "Error starting terraform: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	err = cmd.Wait()
	if err != nil {
		return errors.Wrapf(err, "Error applying AWS IPI modifications: %s %s\n %s", cl.ClusterName, err, buf.String())
	}

	log.WithFields(log.Fields{
		"cluster": infraDetails[0],
	}).Debugf("%s %s", infraDetails[0], buf.String())

	output := strings.Split(buf.String(), "\n")
	log.Infof("✔ AWS IPI modifications were applied for %s type: %s, platform: %s. %s", infraDetails[0], cl.ClusterType, cl.Platform.Name, output[len(output)-2])
	return nil
}

// Create tiller deployment
func (cl *ClusterData) CreateTillerDeployment() error {
	infraDetails, err := cl.ExtractInfraDetails()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	kubeConfigFile := filepath.Join(currentDir, ".config", cl.ClusterName, "auth", "kubeconfig")
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return errors.Wrapf(err, "%s", infraDetails[0])
	}

	log.Infof("Creating tiller deployment for %s, type: %s, platform: %s.", infraDetails[0], cl.ClusterType, cl.Platform.Name)

	tillerFile := filepath.Join(currentDir, "deploy/tiller/tiller.yaml")
	file, err := ioutil.ReadFile(tillerFile)
	if err != nil {
		return errors.Wrapf(err, "Error reading tiller deployment file %s", infraDetails[0])
	}

	acceptedK8sTypes := regexp.MustCompile(`(ServiceAccount|ClusterRoleBinding|Deployment)`)
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
			log.Warnf("The file %s contains K8s object types which are not supported! Skipping object with type: %s", tillerFile, groupVersionKind.Kind)
		} else {
			switch o := obj.(type) {
			case *corev1.ServiceAccount:
				result, err := clientset.CoreV1().ServiceAccounts("kube-system").Create(o)
				if err != nil && strings.Contains(err.Error(), "already exists") {
					log.Debugf("✔ %s %s", err.Error(), infraDetails[0])
				} else if err != nil {
					return err
				} else {
					log.Debugf("✔ Tiler service account was created for %s at: %s", infraDetails[0], result.CreationTimestamp)
				}
			case *rbacv1.ClusterRoleBinding:
				result, err := clientset.RbacV1().ClusterRoleBindings().Create(o)
				if err != nil && strings.Contains(err.Error(), "already exists") {
					log.Debugf("✔ %s %s", err.Error(), infraDetails[0])
				} else if err != nil {
					return errors.Wrapf(err, "%s", infraDetails[0])
				} else {
					log.Debugf("✔ Tiller cluster role binding created for %s at: %s", infraDetails[0], result.CreationTimestamp)
				}
			case *v1.Deployment:
				_, err := clientset.AppsV1().Deployments("kube-system").Create(o)
				if err != nil && strings.Contains(err.Error(), "already exists") {
					log.Infof("✔ %s %s", err.Error(), infraDetails[0])
				} else if err != nil {
					return errors.Wrapf(err, "%s", infraDetails[0])
				} else {
					ctx := context.Background()
					tillerTimeout := 5 * time.Minute
					log.Infof("Waiting up to %v for tiller to be created %s...", tillerTimeout, infraDetails[0])
					tillerContext, cancel := context.WithTimeout(ctx, tillerTimeout)
					wait.Until(func() {
						tillerDeployment, err := clientset.ExtensionsV1beta1().Deployments("kube-system").Get("tiller-deploy", metav1.GetOptions{})
						if err == nil && tillerDeployment.Status.ReadyReplicas > 0 {
							if tillerDeployment.Status.ReadyReplicas == 1 {
								log.Infof("✔ Tiller successfully deployed to %s, ready replicas: %v", infraDetails[0], tillerDeployment.Status.ReadyReplicas)
								cancel()
							} else {
								log.Infof("Still waiting for tiller deployment %s, ready replicas: %v", infraDetails[0], tillerDeployment.Status.ReadyReplicas)
							}
						} else {
							log.Infof("Still waiting for tiller deployment for %s.", infraDetails[0])
						}
					}, 30*time.Second, tillerContext.Done())

					err = tillerContext.Err()
					if err != nil && err != context.Canceled {
						return errors.Wrapf(err, "Error waiting for tiller deployment %s", infraDetails[0])
					}
				}
			}
		}
	}
	return nil
}

var clusterCmd = &cobra.Command{
	Use:   "clusters",
	Short: "Create multiple OCP4 clusters",
	Run: func(cmd *cobra.Command, args []string) {

		if Debug {
			log.SetReportCaller(true)
			log.SetLevel(log.DebugLevel)
		}

		clusters, authConfig, _, openshiftConfig, err := ParseConfigFile()
		if err != nil {
			log.Fatal(err)
		}

		err = GetDependencies(&openshiftConfig)
		if err != nil {
			log.Fatal(err)
		}

		err = TerraformInit()
		if err != nil {
			log.Fatal(err)
		}

		log.Infof("Generating install configs...")
		for _, cl := range clusters {
			err = GenerateConfigs(cl, &authConfig)
			if err != nil {
				log.Fatal(err)
			}
		}

		var wg sync.WaitGroup
		wg.Add(len(clusters))
		for _, cl := range clusters {
			go func(cl ClusterData) {
				err := cl.CreateOcpCluster(&openshiftConfig, &authConfig, &wg)
				if err != nil {
					defer wg.Done()
					log.Fatal(err)
				}
			}(cl)
		}
		wg.Wait()

		log.Infof("✔ Installation completed successfully! The clusters are ready for submariner installation. [ocpup deploy submariner]")
	},
}

func init() {
	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create resources",
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			clusters, _, _, _, err := ParseConfigFile()
			if err != nil {
				log.Fatal(err)
			}

			err = ModifyKubeConfigFiles(clusters)
			if err != nil {
				log.Error(err)
			}
		},
	}
	clusterCmd.Flags().StringVarP(&Username, "user", "u", "", "username to override the current username executing the tool")
	rootCmd.AddCommand(createCmd)
	createCmd.AddCommand(clusterCmd)
}

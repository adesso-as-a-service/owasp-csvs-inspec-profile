# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are from cis-benchmark-docker-inspec

title "Security Verification Requirments for network"

# Control Objectives
    # Choose a good network driver and configure it correctly.
    # Disable unneeded features and apply restrictions.
    # Enforce encryption when transferring data over networks.

#attributes
SWARM_MODE = attribute('swarm_mode')
SWARM_MAX_MANAGER_NODES = attribute('swarm_max_manager_nodes')

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end

control "CSVS-7.3" do                       
  impact 1.0                               
  title "Verify that the Docker userland proxy (which is enabled by default) is disabled."             
  desc "'The docker daemon starts a userland proxy service for port forwarding whenever a port is exposed. Where hairpin NAT is available, this service is generally superfluous to requirements and can be disabled."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'daemon configuration'
  tag 'cis-docker-1.12.0': '2.18'
  ref 'The docker-proxy', url: 'http://windsock.io/the-docker-proxy/'
  ref 'Disable Userland proxy by default', url: 'https://github.com/docker/docker/issues/14856'
  ref 'overlay networking with userland-proxy disabled prevents port exposure', url: 'https://github.com/moby/moby/issues/22741'
  ref 'Bind container ports to the host', url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'

  describe json('/etc/docker/daemon.json') do
    its(['userland-proxy']) { should eq(false) }
  end
  describe processes('dockerd').commands do
    it { should include 'userland-proxy=false' }
  end
end

control "CSVS-7.4" do                       
  impact 1.0                               
  title "Verify that the default bridge (docker0) is not used."             
  desc "Do not use Docker\'s default bridge docker0. Use docker\'s user-defined networks for container networking."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.29'
  ref 'narwhal – secure Docker networking', url: 'https://github.com/nyantec/narwhal'
  ref 'Analysis of Docker Security', url: 'https://arxiv.org/pdf/1501.02967.pdf'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'
  ref 'Ein benutzerdefiniertes Bridge-Netzwerk erstellen und konfigurieren', url: 'https://docs.docker.com/network/bridge/'
  ref 'Ein Overlay-Netzwerk erstellen und konfigurieren', url: 'https://docs.docker.com/network/network-tutorial-overlay/'
  ref 'Ein MACVLAN-Netzwerk erstellen und konfigurieren', url: 'https://docs.docker.com/network/macvlan/'

  describe 'docker-test' do
    skip 'manually configure the bridge docker.'
  end
end

control "CSVS-7.6" do                       
  impact 1.0                               
  title "Verify that dockerd is permitted to modify iptables rules."             
  desc "Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the Linux kernel. Allow the Docker daemon to make changes to the iptables."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'daemon configuration'
  tag 'cis-docker-1.12.0': '2.3'
  ref 'Understand container communication', url: 'https://docs.docker.com/engine/userguide/networking/default_network/container-communication/'

  describe json('/etc/docker/daemon.json') do
    its(['iptables']) { should eq(true) }
  end
end

control "CSVS-7.8" do                       
    impact 1.0                               
    title "Verify that management and data/application traffic is separated by different network interfaces."             
    desc "'By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers. Each outgoing connection will appear to originate from one of the host machine\'s own IP addresses. Only allow container services to be contacted through a specific external interface on the host machine."
  
    tag 'Docker'
    tag 'Level:3'
    tag 'container runtime'
    tag 'cis-docker-1.12.0': '5.13'
    ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'
  
docker.containers.running?.ids.each do |id|
    container_info = docker.object(id)
    next if container_info['NetworkSettings']['Ports'].nil?
    container_info['NetworkSettings']['Ports'].each do |_, hosts|
      next if hosts.nil?
      hosts.each do |host|
        describe host['HostIp'].to_i.between?(1, 1024) do
          it { should_not eq '0.0.0.0' }
        end
      end
    end
  end
end

control "CSVS-7.9" do                       
  impact 1.0                               
  title "Verify that each application (one or more services) is assigned at least one separate, isolated overlay network in order to ensure Layer 3 segmentation."             
  desc "The networking mode on a container when set to \'--net=host\', skips placing the container inside separate network stack. In essence, this choice tells Docker to not containerize the container\'s networking. This would network-wise mean that the container lives 'outside' in the main Docker host and has full access to its network interfaces."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.9'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'
  ref 'Rebooting within docker container actually reboots the host', url: 'https://github.com/docker/docker/issues/6401'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig NetworkMode]) { should_not eq 'host' }
    end
  end

control "CSVS-7.10" do                       
    impact 1.0                               
    title "Verify that encryption between containers or nodes on the overlay network is enabled."             
    desc "'Encrypt data exchanged between containers on different nodes on the overlay network."
  
    tag 'Docker'
    tag 'Level:2,3'
    tag 'daemon configuration'
    tag 'cis-docker-1.12.0': '2.19'
    ref 'Docker swarm mode overlay network security model', url: 'https://docs.docker.com/engine/userguide/networking/overlay-security-model/'
    ref 'Docker swarm container-container traffic not encrypted when inspecting externally with tcpdump', url: 'https://github.com/moby/moby/issues/24253'

    only_if { SWARM_MODE == 'active' }
  if docker_helper.overlay_networks
    docker_helper.overlay_networks.each do |k, _v|
      describe docker_helper.overlay_networks[k] do
        its(['encrypted']) { should_not eq(nil) }
      end
    end
  else
    describe 'Encrypted overlay networks' do
      skip 'Cannot determine overlay networks'
    end
  end
end
end
# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are cis-benchmark-docker-inspec

title "Security Verification Requirments for Containers"

# Control Objectives
    # Ensure that the containers run with the least possible privileges.
    # Harden services inside the container and minimize the attack surface.
    # Leverage security features of the container technology in use.

# attributes
CONTAINER_USER = attribute('container_user')

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end


control "CSVS-3.1" do                       
    impact 1.0                               
    title "Verify that the root user isn't used within containers except during initialization
    and privileges are dropped on completion."             
    desc "An optional description..."
    
    tag 'Docker'
    tag 'Level:2,3'
    tag 'container images'
    tag 'cis-docker-1.12.0': '4.1'
     
    ref 'Having non-root privileges on the host and root inside the container', url: 'https://github.com/docker/docker/issues/2918'
    ref 'Support for user namespaces', url: 'https://github.com/docker/docker/pull/4572'
    ref 'Proposal: Support for user namespaces', url: 'https://github.com/docker/docker/issues/7906'
    ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  
    docker.containers.running?.ids.each do |id|
      describe docker.object(id) do
        its(%w[Config User]) { should_not eq nil }
        its(%w[Config User]) { should eq CONTAINER_USER }
      end
    end
  end

control "CSVS-3.3" do                       
    impact 1.0                               
    title "Verify that within each container image, a new user is created, which is then used to perform all operations within the container."             
    desc "Create a non-root user for the container in the Dockerfile for the container image"
  
    tag 'Docker'
    tag 'Level:3'
    tag 'container images'
    tag 'cis-docker-1.12.0': '4.1'

    ref 'Having non-root privileges on the host and root inside the container', url: 'https://github.com/docker/docker/issues/2918'
    ref 'Support for user namespaces', url: 'https://github.com/docker/docker/pull/4572'
    ref 'Proposal: Support for user namespaces', url: 'https://github.com/docker/docker/issues/7906'
    ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'

    docker.containers.running?.ids.each do |id|
     describe docker.object(id) do
      its(%w[Config User]) { should_not eq nil }
      its(%w[Config User]) { should eq CONTAINER_USER }
     end
    end
end

control "CSVS-3.4" do                       
  impact 1.0                               
  title "Verify that a specific (non-standard) seccomp-profile is applied to each container-based on the needs of the container."             
  desc "Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile disables 44 system calls, out of 313. It should not be disabled unless it hinders your container application usage."

  tag 'Docker'
  tag 'Level:3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.21'

  ref 'New Docker Security Features and What They Mean: Seccomp Profiles', url: 'http://blog.aquasec.com/new-docker-security-features-and-what-they-mean-seccomp-profiles'
  ref 'Docker run reference', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'Seccomp default.json', url: 'https://github.com/moby/moby/blob/master/profiles/seccomp/default.json'
  ref 'Seccomp security profiles for Docker', url: 'https://docs.docker.com/engine/security/seccomp/'
  ref 'SECure COMPuting with filters', url: 'https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt'
  ref 'Capability to specify per volume mount propagation mode', url: 'https://github.com/moby/moby/pull/17034'


  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig SecurityOpt]) { should include(/seccomp/) }
      its(%w[HostConfig SecurityOpt]) { should_not include(/seccomp[=|:]unconfined/) }
    end
  end
end

control "CSVS-3.5" do                       
  impact 1.0                               
  title "Verify that containers cannot be granted any additional privileges during their runtime (--no-new-privileges flag)."             
  desc "Using the --privileged flag gives all Linux Kernel Capabilities to the container thus overwriting the --cap-add and --cap-drop flags. Ensure that it is not used."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.4'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig Privileged]) { should eq false }
      its(%w[HostConfig Privileged]) { should_not eq true }
    end
  end
end

control "CSVS-3.7" do                       
  impact 1.0                               
  title "Verify that the signature of each image is verified before productive usage"             
  desc "Ensure that the container image is written either from scratch or is based on another established and trusted base image downloaded over a secure channel."
  tag 'Docker'
  tag 'Level:3'
  tag 'container images'
  tag 'cis-docker-1.12.0': '4.2'
  ref 'Docker Image Insecurity', url: 'https://titanous.com/posts/docker-insecurity'
  ref 'Docker Hub', url: 'https://hub.docker.com/'
  ref 'Docker 1.3: signed images, process injection, security options, Mac shared directories', url: 'https://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/'
  ref 'Proposal: Provenance step 1 - Transform images for validation and verification', url: 'https://github.com/docker/docker/issues/8093'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Add support for referring to images by digest', url: 'https://github.com/docker/docker/pull/11109'
  ref 'Announcing Docker Trusted Registry 1.4 – New User Interface, Integrated Content Trust and Support for Docker Engine 1.9', url: 'https://blog.docker.com/2015/11/docker-trusted-registry-1-4/'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control "CSVS-3.8" do                       
  impact 1.0                               
  title "Verify that only required software packages are installed in images."             
  desc "Containers tend to be minimal and slim down versions of the Operating System. Do not install anything that does not justify the purpose of container."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'container images'
  tag 'cis-docker-1.12.0': '4.3'

  ref 'Get Started, Part 1: Orientation and setup', url: 'https://docs.docker.com/get-started/'
  ref 'Slimming down your Docker containers with Alpine Linux', url: 'http://www.livewyer.com/blog/2015/02/24/slimming-down-your-docker-containers-alpine-linux'
  ref 'busybox', url: 'https://github.com/progrium/busybox'

  describe 'docker-test' do
    skip 'Do not install unnecessary packages in the container'
  end
end

control "CSVS-3.9" do                       
  impact 1.0                               
  title "Verify that the root file system is mounted in read-only mode."             
  desc "'The container\'s root file system should be treated as a \'golden image\' and any writes to the root filesystem should be avoided. You should explicitly define a container volume for writing."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'docker runtime'
  tag 'cis-docker-1.12.0': '5.12'

  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig ReadonlyRootfs]) { should eq true }
    end
  end
end

control "CSVS-3.11" do                       
  impact 1.0                               
  title "Verify that Dockerfiles use the COPY directive instead of the ADD directive unless the source is fully trusted."             
  desc "An optional description..."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'docker images'
  tag 'cis-docker-1.12.0': '4.9'
  ref 'Best practices for writing Dockerfiles', url: 'https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/'

  docker.images.ids.each do |id|
    describe command("docker --no-trunc history #{id}| grep 'ADD'") do
      its('stdout') { should eq '' }
    end
  end
end

control "CSVS-3.12.1" do                       
  impact 1.0 
  desc "for RDP shuold still be done"                              
  title "Verify that remote management services such as SSH or RDP are disabled or not even installed within containers."             
  desc "'SSH server should not be running within the container. You should SSH into the Docker host, and use nsenter tool to enter a container from a remote host."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.6'
  tag 'SSH'
  ref 'Why you don\'t need to run SSHd in your Docker containers', url: 'https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/'

  docker.containers.running?.ids.each do |id|
    execute_command = 'docker exec ' + id + ' ps -e'
    describe command(execute_command) do
      its('stdout') { should_not match(/ssh/) }
    end
  end
end

control "CSVS-3.14" do                       
  impact 1.0                               
  title "Verify that the number of allowed processes within a container is precisely defined and limited to this value by using --pids-limit."             
  desc "Use --pids-limit flag at container runtime."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.28'
  ref 'Add PIDs cgroup support to Docker', url: 'https://github.com/moby/moby/pull/18697'
  ref 'docker run', url: 'https://docs.docker.com/engine/reference/commandline/run/'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its('HostConfig.PidsLimit') { should_not cmp 0 }
      its('HostConfig.PidsLimit') { should_not cmp(-1) }
    end
  end
end

control "CSVS-3.15" do                       
  impact 1.0                               
  title "Verify that the Docker socket isn't mounted inside any container unless they are used for monitoring or administration. If access to the Docker socket is required, check if read-only access is sufficient and limit the access of the container accordingly."             
  desc "The docker socket (docker.sock) should not be mounted inside a container."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.31'

  ref 'The Dangers of Docker.sock', url: 'https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/'
  ref 'Docker-in-docker vs mounting /var/run/docker.sock', url: 'https://forums.docker.com/t/docker-in-docker-vs-mounting-var-run-docker-sock/9450/2'
  ref 'Is `-v /var/run/docker.sock:/var/run/docker.sock` a ticking time bomb', url: 'https://github.com/moby/moby/issues/21109'

  docker.containers.running?.ids.each do |id|
    docker.object(id).Mounts.each do |mount|
      describe mount do
        its('Source') { should_not include 'docker.sock' }
      end
    end
  end
end

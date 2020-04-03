# encoding: utf-8
# copyright: 2020, Roozbeh Rashedi
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
  desc "An optional description..."
  # check if it controls each container image?!
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
  


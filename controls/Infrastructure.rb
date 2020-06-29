# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are cis-benchmark-docker-inspec

title "Security Verification Requirments for Infrastructure"

# Control Objectives
    # Ensure that the infrastructure provides adequate resources.
    # Harden the base infrastructure including the container platform.
   
# attributes
APP_ARMOR_PROFILE = attribute('app_armor_profile')
SELINUX_PROFILE = attribute('selinux_profile')


# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end

control "CSVS-2.5" do                       
  impact 1.0                                
  title "Verify that the resources available to containers are limited (ulimit)."
  desc "..."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'docker daemon configuration'
  tag 'cis-docker-1.12.0': '2.7'

  ref 'Docker daemon deafult ulimits', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#default-ulimits'
  
  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits', 'nproc']) { should eq('1024:2408') }
    its(['default-ulimits', 'nofile']) { should eq('100': '200') }
  end
end

control "CSVS-2.6.1" do                       
    impact 1.0                                
    title "Verify that SELinux or AppArmor is enabled and running on all nodes as well as for dockerd."
    desc "..."
  # verifying AppArmor
    tag 'Docker'
    tag 'Level:3'
    tag 'AppArmor'
    tag 'contianer runtime'
    tag 'cis-docker-1.12.0': '5.1'
    
    ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/'
    ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
    ref 'AppArmor security profiles for Docker', url: 'https://docs.docker.com/engine/security/apparmor/'
    
   only_if { %w[ubuntu debian].include? os[:name] }
   docker.containers.running?.ids.each do |id|
     describe docker.object(id) do
       its(['AppArmorProfile']) { should include(APP_ARMOR_PROFILE) }
       its(['AppArmorProfile']) { should_not eq nil }
     end
  end
end

control "CSVS-2.6.2" do                        
  impact 1.0                                
  title "Create /tmp directory"             
  desc "An optional description..."
  #verifying SELinux
  
  tag 'Docker'
  tag 'Level:3'
  tag 'AppArmor'
  tag 'contianer runtime'
  tag 'cis-docker-1.12.0': '5.2'

  ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/'
  ref 'Secure Engine', url: 'https://docs.docker.com/engine/security/'
  ref 'AppArmor security profiles for Docker', url: 'https://docs.docker.com/engine/security/apparmor/'
  ref 'Bug: Wrong SELinux label for devmapper device', url: 'https://github.com/docker/docker/issues/22826'
  ref 'Bug: selinux break docker user namespace', url: 'https://bugzilla.redhat.com/show_bug.cgi?id=1312665'
  ref 'Security-Enhanced Linux', url: 'https://docs-old.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/'

  only_if { %w[centos redhat].include? os[:name] }
  describe json('/etc/docker/daemon.json') do
    its(['selinux-enabled']) { should eq(true) }
  end

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[HostConfig SecurityOpt]) { should_not eq nil }
      its(%w[HostConfig SecurityOpt]) { should include(SELINUX_PROFILE) }
    end
  end
end

control "CSVS-2.10" do                       
    impact 1.0                               
    title "Verify that permissions to the configuration of dockerd is restricted to users that actually need access to it and are properly logged."             
    desc 'The Docker daemon currently requires \'root\' privileges. A user added to the \'docker\' group gives him full \'root\' access rights.'
  
    tag 'Docker'
    tag 'Level:1,2,3'
    tag 'host configuration'
    tag 'cis-docker-1.12.0': '1.6'
  
    ref 'Docker Engine Security', url: 'https://docs.docker.com/engine/security/'
    ref 'On Docker security: \'docker\' group considered harmful', url: 'https://www.zopyx.com/andreas-jung/contents/on-docker-security-docker-group-considered-harmful'
    ref 'Why we don\'t let non-root users run Docker in CentOS, Fedora, or RHEL', url: 'http://www.projectatomic.io/blog/2015/08/why-we-dont-let-non-root-users-run-docker-in-centos-fedora-or-rhel/'
  
    
  describe group('docker') do
    it { should exist }
  end

  describe etc_group.where(group_name: 'docker') do
    its('users') { should include TRUSTED_USER }
  end
end

control "CSVS-2.15.1" do                       
    impact 1.0                               
    title "Verify that direct access to nodes (e.g. via SSH or RDP) is restricted as much as possible."             
    desc "An optional description..."
  # do not run ssh within contianers
    tag 'Docker'
    tag 'Level:1,2,3'
    tag 'container runtime'
    tag 'cis-docker-1.12.0': '5.6'
    
    ref 'Why you don\'t need to run SSHd in your Docker containers', url: 'https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/'

    docker.containers.running?.ids.each do |id|
        execute_command = 'docker exec ' + id + ' ps -e'
        describe command(execute_command) do
          its('stdout') { should_not match(/ssh/) }
        end
      end
    end

  
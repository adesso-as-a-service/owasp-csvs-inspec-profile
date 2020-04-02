# encoding: utf-8
# copyright: 2020, Roozbeh Rashedi

title "Security Verification Requirments"

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

control "CSVS-2.6" do                       
    impact 1.0                                
    title "Verify that SELinux or AppArmor is enabled and running on all nodes as well as for dockerd."
    desc "..."
  
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
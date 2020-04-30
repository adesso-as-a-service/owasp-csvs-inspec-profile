# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are from cis-benchmark-docker-inspec

title "Security Verification Requirments for Orchestration Management"

# Control Objectives
    # Uptime for the orchestrator is guaranteed.
    # The orchestrator is hardened.
    # Interaction with the orchestrator is mostly automated to avoid human errors.

# attributes
CONTAINER_USER = attribute('container_user')

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end

control "CSVS-4.2" do                       
    impact 1.0                               
    title "Verify that an odd number of manager nodes is deployed with a minimum of three nodes."             
    desc "Ensure that the minimum number of required manager nodes is created in a swarm."
    tag 'Docker'
    tag 'Level:1,2,3'
    tag 'daemon configuration'
    tag 'cis-docker-1.12.0': '2.16' 
    ref 'Manage nodes in a swarm', url: 'https://docs.docker.com/engine/swarm/manage-nodes/'
    ref 'Administer and maintain a swarm of Docker Engines', url: 'https://docs.docker.com/engine/swarm/admin_guide/'
    
    only_if { SWARM_MODE == 'active' }
    describe docker.info do
    its('Swarm.Managers') { should cmp <= SWARM_MAX_MANAGER_NODES }
    end
end
  
  
  
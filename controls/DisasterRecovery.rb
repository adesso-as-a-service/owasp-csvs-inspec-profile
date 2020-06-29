# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are from cis-benchmark-docker-inspec

title "Security Verification Requirments for Containers"

# Control Objectives
    # Protect sensitive information.
    # Verify secure handling of cryptographic material.
    # Rotate cryptographic keys on a regular basis.

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end
  
control "CSVS-11.5" do                       
  impact 1.0                               
  title "Verify that an on-failure restart policy is enabled for each container"             
  desc "An optional description..."
  desc "Optional: Set the \'on-failure\' container restart policy to 5"

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.14'
  ref 'Start containers automatically', url: 'https://docs.docker.com/engine/admin/start-containers-automatically/'

  docker.containers.running?.ids.each do |id|
    describe.one do
      describe docker.object(id) do
        its(%w[HostConfig RestartPolicy Name]) { should eq 'no' }
      end
      describe docker.object(id) do
        its(%w[HostConfig RestartPolicy Name]) { should eq 'on-failure' }
        its(%w[HostConfig RestartPolicy MaximumRetryCount]) { should eq 5 }
      end
    end
  end
end
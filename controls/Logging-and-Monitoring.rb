# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are from cis-benchmark-docker-inspec

title "Security Verification Requirments for Containers"

# Control Objectives
    # Protect sensitive information.
    # Verify secure handling of cryptographic material.
    # Rotate cryptographic keys on a regular basis.

# attributes
CONTAINER_USER = attribute('container_user')

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end

control "CSVS-9.2" do                       
  impact 1.0                               
  title "Verify that the used resources at both node and container level are monitored."             
  desc "'Containers might run services that are critical for your business. Monitoring their usage, performance and metering would be of paramount importance."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'Docker security operations'
  tag 'cis-docker-1.12.0': '6.2'
  ref 'Runtime metrics', url: 'https://docs.docker.com/engine/admin/runmetrics/'
  ref 'cAdvisor (Container Advisor)', url: 'https://github.com/google/cadvisor'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'

  describe 'docker-test' do
    skip 'Monitor Docker containers usage, performance and metering'
  end
end

control "CSVS-9.4-1" do                       
  impact 1.0                               
  title "Verify that Docker's health checking functionality is used for all containers and their status is monitored."             
  desc "Add HEALTHCHECK instruction in your docker container images to perform the health check on running containers."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container images'
  tag 'cis-docker-1.12.0': '4.6'
  ref 'Add support for user-defined healthchecks', url: 'https://github.com/moby/moby/pull/22719'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its(%w[Config Healthcheck]) { should_not eq nil }
    end
  end
end

control "CSVS-9.4-2" do                       
  impact 1.0                               
  title "Verify that Docker's health checking functionality is used for all containers and their status is monitored."             
  desc "If the container image does not have an HEALTHCHECK instruction defined, use --health-cmd parameter at container runtime for checking container health."
  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.26'
  ref 'Add support for user-defined healthchecks', url: 'https://github.com/moby/moby/pull/22719'

  docker.containers.running?.ids.each do |id|
    describe docker.object(id) do
      its('State.Health.Status') { should eq 'healthy' }
    end
  end
end
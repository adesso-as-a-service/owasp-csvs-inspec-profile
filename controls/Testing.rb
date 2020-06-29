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

control "CSVS-" do                       
  impact 1.0                               
  title "Verify that nodes as well as the Docker Engine are up to date."             
  desc "'There are frequent releases for Docker software that address security vulnerabilities,product bugs and bring in new functionality. Keep a tab on these product updates and upgrade as frequently as when new security vulnerabilities are fixed or deemed correct for your organization."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'host configuration'
  tag 'cis-docker-1.12.0': '1.5'
  ref 'Docker installation', url: 'https://docs.docker.com/engine/installation/'
  ref 'Docker releases', url: 'https://github.com/moby/moby/releases/tag/v17.03.2-ce'
  ref 'About Docker EE', url: 'https://docs.docker.com/enterprise/'

  describe docker do
    its('version.Client.Version') { should cmp >= '17.06' }
    its('version.Server.Version') { should cmp >= '17.06' }
  end
end
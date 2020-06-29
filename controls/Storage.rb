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

control "CSVS-8.4" do                       
  impact 1.0                               
  title "Verify that persistent data is never stored directly inside a container, but on a corresponding docker volume or mount point instead."             
  desc "All Docker containers and their data and metadata is stored under /var/lib/docker directory. By default, /var/lib/docker would be mounted under / or /var partitions based on availability."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'host configuration'
  tag 'cis-docker-1.12.0': '2.14'

  describe mount('/var/lib/docker') do
    it { should be_mounted }
  end
end
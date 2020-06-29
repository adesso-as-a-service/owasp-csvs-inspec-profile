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

control "CSVS-6.2" do                       
  impact 1.0                               
  title "Verify that Docker Content Trust is enabled and enforced."             
  desc "Content trust is disabled by default. You should enable it."

  tag 'Docker'
  tag 'Level:1'
  tag 'daemon configuration'
  tag 'cis-docker-1.12.0': '4.5'
  ref 'Content trust in Docker', url: 'https://docs.docker.com/engine/security/trust/content_trust/'
  ref 'Notary', url: 'https://docs.docker.com/engine/reference/commandline/cli/#notary'
  ref 'Environment variables', url: 'https://docs.docker.com/engine/reference/commandline/cli/#environment-variables'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control "CSVS-6.3" do                       
  impact 1.0                               
  title "Sensitive information may never be part of a Dockerfile or Docker-Compose file. In particular, verify that e.g. Docker secrets are used for handling sensitive information like API keys and passwords."
  desc "Do not store any secrets in Dockerfiles."

  tag 'Docker'
  tag 'Level:1,2,3'
  tag 'daemon configuration'
  tag 'cis-docker-1.12.0': '4.10'
  ref 'Secrets: write-up best practices, do\'s and don\'ts, roadmap', url: 'https://github.com/moby/moby/issues/13490'
  ref 'The Twelve-Factor App', url: 'https://12factor.net/config'
  ref 'Twitter\'s Vine Source code dump', url: 'https://avicoder.me/2016/07/22/Twitter-Vine-Source-code-dump/'

  describe 'docker-test' do
    skip 'Manually verify that you have not used secrets in images'
  end
end



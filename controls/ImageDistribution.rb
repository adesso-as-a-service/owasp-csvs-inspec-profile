# encoding: utf-8
# copyright: 2020, adesso as a service GmbH
# Reference for some controls are from cis-benchmark-docker-inspec

title "Security Verification Requirments for Image Distribution"

# Control Objectives
    # Images are hardened.
    # No sensitive data is stored inside of images.
    # Images are checked for vulnerable components.

# check if docker exists
only_if('docker not found') do
    command('docker').exist?
  end

control "CSVS-5.3" do                       
  impact 1.0                               
  title "Verify that all images undergo regular automated security scans."             
  desc "Ensure that the container image is written either from scratch or is based on another established and trusted base image downloaded over a secure channel."
  #not sure if the security check for the trusted images meets the requirement.(tbd!)

  tag 'Docker'
  tag 'Level:2,3'
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

control "CSVS-5.4" do                       
  impact 1.0                               
  title "Verify that containers are always created based on the most recent corresponding image and not local caches."             
  desc "Always ensure that you are using the latest version of the image within your repository and not the cached older versions."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'container runtime'
  tag 'cis-docker-1.12.0': '5.27'

  ref 'Modifying trusted/untrusted pull behavior for create/run/build', url: 'https://github.com/moby/moby/pull/16609'

  describe 'docker-test' do
    skip 'Verify that containers are always created based on the most recent corresponding image and not local caches.'
  end
end

control "CSVS-5.5" do                       
  impact 1.0                               
  title "Verify that all images are using tags whereas only production/master is allowed to use the default latest tag."             
  desc "Do not keep a large number of container images on the same host. Use only tagged images as appropriate."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'docker security operations'
  tag 'cis-docker-1.12.0': '6.4'
  ref 'Clean up unused Docker Containers and Images', url: 'http://craiccomputing.blogspot.de/2014/09/clean-up-unused-docker-containers-and.html'
  ref 'Command to remove all unused images', url: 'https://forums.docker.com/t/command-to-remove-all-unused-images/20/8'
  ref 'docker rmi --unused', url: 'https://github.com/moby/moby/issues/9054'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Add support for referring to images by digest', url: 'https://github.com/moby/moby/pull/11109'

  instantiated_images = command('docker ps -qa | xargs docker inspect -f \'{{.Image}}\'').stdout.split
  all_images = command('docker images -q --no-trunc').stdout.split
  diff = all_images - instantiated_images

  describe diff do
    it { should be_empty }
  end
end
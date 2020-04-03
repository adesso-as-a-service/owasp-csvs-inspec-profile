# copyright: 2018, The Authors

title "sample section"

# you can also use plain tests
describe file("/tmp") do
  it { should be_directory }
end

# you add controls here
control "tmp-1.0" do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title "Create /tmp directory"             # A human-readable title
  desc "An optional description..."
  describe file("/tmp") do                  # The actual test
    it { should be_directory }
  end
end

#Example for CSVS

control "CSVS-" do                       
  impact 1.0                               
  title "Create /tmp directory"             
  desc "An optional description..."

  tag 'Docker'
  tag 'Level:2,3'
  tag 'daemon configuration'
  tag 'cis-docker-1.12.0': '2.14'

  describe file("/tmp") do                  
    it { should be_directory }
  end
end
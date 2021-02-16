# 14-4-4-X-Content-Type-Options.rb


title 'Content Type Options'

URL = <insert_url_here>

# you can also use plain tests
#describe file('/tmp') do
#  it { should be_directory }
#end

# you add controls here
control 'HTTP Header - Content Type Options' do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title 'Content type Options = no sniff'
  desc 'All responses should contain X-Content-Type-Options=nosniff'
  tag 'ASVS-14.4.4'
  tag 'ISO27001-14.1.2'
  describe http('$URL') do                  # The actual test
    its('headers.x-content-type-options') { should cmp 'nosniff' } 
  end
end
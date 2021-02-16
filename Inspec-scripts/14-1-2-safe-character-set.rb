title 'Safe character set'

URL = <insert_url_here>

# you can also use plain tests
#describe file('/tmp') do
#  it { should be_directory }
#end

# you add controls here

control 'HTTP Header - Content type' do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title 'Safe character set'             # A human-readable title
  desc 'HTTP response contains content type header with safe character set'
  tag 'ASVS-14.4.1'
  tag 'ISO27001-14.1.2'
  describe http('$URL') do                  # The actual test
    its('headers.Content-type') { should cmp 'text/html; charset=utf-8' }
    its('headers.Content-type') { should cmp 'text/html; charset=iso-8859-1' }
  end
end
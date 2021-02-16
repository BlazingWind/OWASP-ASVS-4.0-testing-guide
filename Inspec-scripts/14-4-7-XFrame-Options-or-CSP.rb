title 'X-Frame-Options or CSP'

URL = <insert_url_here>

# you can also use plain tests
#describe file('/tmp') do
#  it { should be_directory }
#end

# you add controls here

control 'HTTP Headers - X-Frame Options or CSP' do                        # A unique ID for this control
  impact 0.7                                # The criticality, if this control fails.
  title 'X Frame Options or Content Security policy set'             # A human-readable title
  desc 'All responses should include X Frame Options or Content Security Policy'
  tag 'ASVS-14.4.7'
  tag 'ISO27001-14.1.2'
  describe http('$URL').headers do                  # The actual test
    its('x-frame-options') { should cmp 'SAMEORIGIN' }
  end
end

# This test is currently missing the validation for CSP
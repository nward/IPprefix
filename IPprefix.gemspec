Gem::Specification.new do |s|
  s.name              = "IPprefix"
  s.version           = "0.0.1"
  s.platform          = Gem::Platform::RUBY
  s.authors           = ["Nathan Ward"]
  s.email             = ["nward@braintrust.co.nz"]
  s.homepage          = "http://github.com/nward/IPprefix"
  s.summary           = "Native, fast IP prefix handling code"
  s.description       = "Includes the IPprefix class, a fast class for handling IP prefixes."

  s.required_rubygems_version = ">= 1.3.6"
  
  s.files         = `git ls-files`.split("\n")
  
  s.extensions = "ext/extconf.rb"
end

Gem::Specification.new do |s|
  s.name              = "IPprefix"
  s.version           = "0.0.1"
  s.platform          = Gem::Platform::RUBY
  s.authors           = ["Nathan Ward"]
  s.email             = ["nward@braintrust.co.nz"]
  s.homepage          = "http://github.com/nward"
  s.summary           = "IPprefix"
  s.description       = "IPprefix"

  s.required_rubygems_version = ">= 1.3.6"
  
  s.files         = `git ls-files`.split("\n")
  
  s.extensions = "ext/extconf.rb"
end

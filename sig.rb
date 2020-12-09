require 'openssl'
require 'base64'
f = File.open("private.pem")
s = f.read

keypair = OpenSSL::PKey::RSA.new(s)

signature = "cN13xMr9+gH2IFkEDidUmPwrXnlolH/59tKWtnDGHA/6o+1TQZ4MNcLCzhb3SOwdNSubiUZK2Z+9U5KScHTjdGomA5orLx2CFzvccGQw77Cm9M6TCdHwOWfnOVk59Aexs1pPbzTv1ahHwPn1qIZht71kUoSG/jS+x3A6V3zkEgXmNabYQVJP5Bqf7J5wrP0F2DjH1CCu0Ic1/kw41aoL7cXv2EQcS9ZOlBTE8nZpt132yjEaPQgXAdImdsN7PRxqvcm9dHYZaSpq+IVc/VGI5QnFUBYsmDqEwE0RbDVvUv+uCNHF0IpRQrCwq3VFw4C65Tc3smeV63KZRLCUKioU2A=="
compare_signed_string = 
"""(request-target): post /inbox
host: imastodon.net
date: Wed, 09 Dec 2020 21:33:18 GMT"""

p Base64.strict_encode64(keypair.sign(OpenSSL::Digest.new('SHA256'),compare_signed_string))
p compare_signed_string
p signature
p keypair.verify(OpenSSL::Digest.new('SHA256'), Base64.decode64(signature),compare_signed_string)

public_key = keypair.public_key
File.open("ruby_public_key.pem", "w") do |f|
  f.write(public_key.export)
end
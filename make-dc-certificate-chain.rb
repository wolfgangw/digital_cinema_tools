#!/usr/bin/env ruby
#
# Wolfgang Woehl v0.2010.11.16
#
# Create 3 related digital cinema compliant certificates,
# verify root certificate -> intermediate ->  leaf certificate
# and concatenate into a certificate chain.
#
# Requires ruby and openssl
#
# Proof of concept. In real-world applications you'd want 
# to secure keys with appropriate file permissions and 
# passphrases. Also you'd want to set up some infrastructure 
# to allow for various intermediate and leaf certificates and 
# to enable the relevant tools to find your keys and certificates.
#
# Script, in principle, does the same thing 3 times,
# once to create a root authority, then an intermediate
# authority and finally a leaf at the end of the branch:
#
#   a) Create a private/public key pair
#   b) define digital-cinema-specific properties of the corresponding, to-be-created certificate
#   c) Issue a request for signature (which is the public key component plus metadata)
#   d) Sign and thereby issue a signed certificate (self-signed in the case of the root certificate)
#
# The relation between 2 certificates is established in d)
#
# Intentionally no ruby-specific openssl bindings here,
# merely building shell calls to openssl.
#    - So why is this a ruby script then?
#    - Because I nearly broke my bones trying to properly quote 
#      the required dnq's in bash. Solutions much appreciated
#
# No directory and file checks here. Watch where you run it.
#
# $ mkdir certstore
# $ cd certstore
# $ make-dc-certificate-chain.rb
#     (creates keys and certificates in the current directory)
#
# Use leaf.key to sign files, for example
#
# $ xmlsec --sign --privkey-pem leaf.key --trusted-pem intermediate.signed.pem --trusted-pem ca.self-signed.pem presigned_cpl.xml
#
# where presigned_cpl.xml is an XML Signature template, containing a 
# composition playlist, a signer fragment and a signature block,
# containing a signed info fragment and a signature value stub.
#
# See https://github.com/wolfgangw/digital_cinema_tools/blob/master/cinemaslides
# for one possible implementation.
#


# Clean up previous runs
old = Dir.glob( [ 'ca.*', 'intermediate.*', 'leaf.*', 'dc-certificate-chain', 'signer.key' ] )
old.each do |file|
  File.delete( file )
end


### Make a self-signed root certificate. This will act as trust anchor for your certificate chain

# Generate CA key pair (private and public component)
`openssl genrsa -out ca.key 2048`

# Note basicConstraints and keyUsage
ca_cnf = <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions	= v3_ca
[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:3
keyUsage = keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
[ req_distinguished_name ]
O = Unique organization name
OU = Organization unit
CN = Entity and dnQualifier
EOF
File.open( 'ca.cnf', 'w' ) { |f| f.write( ca_cnf ) }

# Subject dnQualifier (Public key thumbprint, see SMPTE 430-2-2006 sections 5.3.1, 5.4 and DCI CTP section 2.1.11)
ca_dnq = `openssl rsa -outform PEM -pubout -in ca.key | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64`.chomp
ca_dnq = ca_dnq.gsub( '/', '\/' ) # can have values like '0Za8/aABE05Aroz7le1FOpEdFhk=', note the '/'. protect for name parser
# The following simply concatenates the dnq. Somehow I have a feeling that that's not quite right. Someone knows?
ca_subject = '/O=example.org/OU=csc.example.org/CN=.dcstore.ROOT/dnQualifier=' + ca_dnq

# Generate self-signed certificate
`openssl req -new -x509 -sha256 -config ca.cnf -days 365 -set_serial 5 -subj "#{ ca_subject }" -key ca.key -outform PEM -out ca.self-signed.pem`
###


### Make an intermediate certificate, issued/signed by the root certificate and root's private key

# Generate intermediate's key pair
`openssl genrsa -out intermediate.key 2048`

# Note basicConstraints pathlen
inter_cnf = <<EOF
[ default ]
distinguished_name	= req_distinguished_name
x509_extensions	= v3_ca
[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:2
keyUsage = keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
[ req_distinguished_name ]
O = Unique organization name
OU = Organization unit
CN = Entity and dnQualifier
EOF
File.open( 'intermediate.cnf', 'w' ) { |f| f.write( inter_cnf ) }

# equiv.   openssl x509 -pubkey -noout -in intermediate.signed.pem | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64
inter_dnq = `openssl rsa -outform PEM -pubout -in intermediate.key | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64`.chomp
inter_dnq = inter_dnq.gsub( '/', '\/' )
inter_subject = "/O=example.org/OU=csc.example.org/CN=.dcstore.INTERMEDIATE/dnQualifier=" + inter_dnq

# Request signing for intermediate certificate
`openssl req -new -config intermediate.cnf -days 365 -subj "#{ inter_subject }" -key intermediate.key -out intermediate.csr`
# Issue/Sign with root certificate/private key
`openssl x509 -req -sha256 -days 365 -CA ca.self-signed.pem -CAkey ca.key -set_serial 6 -in intermediate.csr -extfile intermediate.cnf -extensions v3_ca -out intermediate.signed.pem`
###


### Make a leaf certificate, issued/signed by the intermediate certificate and intermediate private key
# Use the leaf certificate to sign content (like CPLs and PKLs)

# Generate leaf's key pair
`openssl genrsa -out leaf.key 2048`

# Note basicConstraints and keyUsage
leaf_cnf = <<EOF
[ default ]
distinguished_name	= req_distinguished_name
x509_extensions	= v3_ca
[ v3_ca ]
# pathlen not needed. Would the cert be rejected because of pathlen marked critical?
# Answer: no. see SMPTE 430-2-2006 section 6.2 Validation Rules - Check 5
basicConstraints = critical,CA:false
keyUsage = digitalSignature,keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
[ req_distinguished_name ]
O = Unique organization name
OU = Organization unit
CN = Entity and dnQualifier
EOF
File.open( 'leaf.cnf', 'w' ) { |f| f.write( leaf_cnf ) }

# equiv.  openssl x509 -pubkey -noout -in leaf.signed.pem | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64
leaf_dnq = `openssl rsa -outform PEM -pubout -in leaf.key | openssl base64 -d | dd bs=1 skip=24 2>/dev/null | openssl sha1 -binary | openssl base64`.chomp
leaf_dnq = leaf_dnq.gsub( '/', '\/' )
# Note the CN list of roles (RO=rights owner, SM=security manager, CS=content signer)
# Roles are separated by space character and by leftmost period character from the unique entity label
leaf_subject = "/O=example.org/OU=csc.example.org/CN=RO SM CS.dcstore.LEAF/dnQualifier=" + leaf_dnq

# Request signing for leaf certificate
`openssl req -new -config leaf.cnf -days 365 -subj "#{ leaf_subject }" -key leaf.key -outform PEM -out leaf.csr`
# Issue/Sign with intermediate certificate/private key
`openssl x509 -req -sha256 -days 365 -CA intermediate.signed.pem -CAkey intermediate.key -set_serial 7 -in leaf.csr -extfile leaf.cnf -extensions v3_ca -out leaf.signed.pem`
###


### Print out issuer and subject information for each of the generated certificates
puts "\n+++ Certificate info +++\n"
[ [ 'Self-signed CA certificate (issuer == subject)', 'ca.self-signed.pem' ], [ 'Intermediate certificate', 'intermediate.signed.pem' ], [ 'Leaf certificate', 'leaf.signed.pem' ] ].each do |t|
  puts "\n#{ t.first } (#{ t.last }):\n#{ `openssl x509 -noout -subject -in #{ t.last }` }   signed by\n #{ `openssl x509 -noout -issuer -in #{ t.last }` }"
end


# For illustration: Verify certificates and write certificate chain
puts "\n+++ Verify certificates and write dc-certificate-chain +++\n\n"
puts `openssl verify -CAfile ca.self-signed.pem ca.self-signed.pem`
`cp ca.self-signed.pem dc-certificate-chain`
puts `openssl verify -CAfile dc-certificate-chain intermediate.signed.pem`
`cat intermediate.signed.pem >> dc-certificate-chain`
puts `openssl verify -CAfile dc-certificate-chain leaf.signed.pem`
`cat leaf.signed.pem >> dc-certificate-chain`

`ln -s leaf.key signer.key`

puts "\nDONE"

